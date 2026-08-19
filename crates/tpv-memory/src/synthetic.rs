//! A memory image built from scratch, for testing the analysis against.
//!
//! Real captures cannot be committed to a repository: they are gigabytes, they
//! contain whoever's secrets were in RAM, and they pin the tests to one Windows
//! build. Building an image instead means the page tables, the process list and
//! the pool allocations are all constructed to spec, and every value the
//! analysis recovers can be checked against what was deliberately put there.
//!
//! The structure offsets used here are intentionally *not* those of any shipped
//! Windows. If the calibration in [`crate::profile`] were quietly falling back
//! on hardcoded constants, these tests would fail — which is the point.

use crate::image::PhysicalMemory;

pub const PAGE: u64 = 0x1000;

/// Where fields sit inside the synthetic `_EPROCESS`.
pub mod layout {
    /// `_KPROCESS.DirectoryTableBase`, at the real Windows offset because the
    /// pool-scan calibration measures against it.
    pub const DTB: u64 = 0x28;
    pub const CREATE_TIME: u64 = 0x468;
    pub const EXIT_TIME: u64 = 0x470;
    pub const UNIQUE_PROCESS_ID: u64 = 0x4a0;
    pub const ACTIVE_PROCESS_LINKS: u64 = 0x4a8;
    pub const INHERITED_FROM_PID: u64 = 0x5c0;
    pub const PEB: u64 = 0x5d0;
    pub const IMAGE_FILE_NAME: u64 = 0x630;
    pub const SIZE: u64 = 0x700;
}

/// PEB and process-parameter offsets, which are ABI and so are the real ones.
mod user {
    pub const PEB_LDR: u64 = 0x18;
    pub const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    pub const PARAMS_CURRENT_DIRECTORY: u64 = 0x38;
    pub const PARAMS_IMAGE_PATH: u64 = 0x60;
    pub const PARAMS_COMMAND_LINE: u64 = 0x70;
    pub const LDR_IN_LOAD_ORDER: u64 = 0x10;
    pub const ENTRY_DLL_BASE: u64 = 0x30;
    pub const ENTRY_SIZE_OF_IMAGE: u64 = 0x40;
    pub const ENTRY_FULL_NAME: u64 = 0x48;
}

const PRESENT_WRITE: u64 = 0b11;
const PFN_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// A process to place in the image.
pub struct ProcessSpec {
    pub name: &'static str,
    pub pid: u64,
    pub ppid: u64,
    pub create_time: u64,
    pub exit_time: u64,
    /// When false, the process gets a pool allocation but is left out of
    /// `ActiveProcessLinks` — the state a rootkit leaves behind.
    pub linked: bool,
    pub command_line: Option<&'static str>,
    pub image_path: Option<&'static str>,
    pub modules: &'static [(&'static str, u64, u32)],
}

impl ProcessSpec {
    pub fn kernel(name: &'static str, pid: u64, ppid: u64, create_time: u64) -> Self {
        Self {
            name,
            pid,
            ppid,
            create_time,
            exit_time: 0,
            linked: true,
            command_line: None,
            image_path: None,
            modules: &[],
        }
    }

    pub fn user(
        name: &'static str,
        pid: u64,
        ppid: u64,
        create_time: u64,
        command_line: &'static str,
    ) -> Self {
        Self {
            name,
            pid,
            ppid,
            create_time,
            exit_time: 0,
            linked: true,
            command_line: Some(command_line),
            image_path: None,
            modules: &[],
        }
    }

    pub fn unlinked(mut self) -> Self {
        self.linked = false;
        self
    }

    pub fn exited(mut self, at: u64) -> Self {
        self.exit_time = at;
        self
    }

    pub fn with_modules(mut self, modules: &'static [(&'static str, u64, u32)]) -> Self {
        self.modules = modules;
        self
    }
}

pub struct Builder {
    bytes: Vec<u8>,
    next: u64,
    kernel_pml4: u64,
    next_kernel_va: u64,
}

/// Where the synthetic kernel puts things. Any canonical upper-half base works.
const KERNEL_VA_BASE: u64 = 0xFFFF_8001_0000_0000;
const USER_VA_BASE: u64 = 0x0000_0000_7000_0000;

impl Builder {
    pub fn new(size_bytes: usize) -> Self {
        let mut b = Self {
            bytes: vec![0u8; size_bytes],
            // Leave the first megabyte alone; on a real machine it is firmware,
            // and starting above it keeps physical address zero meaningless.
            next: 0x10_0000,
            kernel_pml4: 0,
            next_kernel_va: KERNEL_VA_BASE,
        };
        b.kernel_pml4 = b.alloc_page();
        b.make_self_referential(b.kernel_pml4);
        b
    }

    pub fn kernel_dtb(&self) -> u64 {
        self.kernel_pml4
    }

    pub fn alloc_page(&mut self) -> u64 {
        let pa = self.next;
        self.next += PAGE;
        assert!(
            (self.next as usize) <= self.bytes.len(),
            "the synthetic image is too small for what the test asked for"
        );
        pa
    }

    fn reserve_kernel_va(&mut self, pages: u64) -> u64 {
        let va = self.next_kernel_va;
        self.next_kernel_va += pages * PAGE + PAGE;
        va
    }

    pub fn write(&mut self, pa: u64, data: &[u8]) {
        let at = pa as usize;
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }

    pub fn write_u64(&mut self, pa: u64, v: u64) {
        self.write(pa, &v.to_le_bytes());
    }

    pub fn write_u32(&mut self, pa: u64, v: u32) {
        self.write(pa, &v.to_le_bytes());
    }

    pub fn write_u16(&mut self, pa: u64, v: u16) {
        self.write(pa, &v.to_le_bytes());
    }

    fn read_u64(&self, pa: u64) -> u64 {
        let at = pa as usize;
        u64::from_le_bytes(self.bytes[at..at + 8].try_into().unwrap())
    }

    /// Give a page-table root the self-map Windows installs.
    ///
    /// The index is in the kernel half, as it must be — the self-map is a
    /// kernel-only window — but is deliberately not the historical 0x1ed, so the
    /// discovery code has to find it by its property rather than its position.
    fn make_self_referential(&mut self, pml4: u64) {
        self.write_u64(pml4 + 0x1a7 * 8, pml4 | PRESENT_WRITE);
    }

    /// A fresh address space that shares the kernel's upper half.
    pub fn new_address_space(&mut self) -> u64 {
        let pml4 = self.alloc_page();
        for i in 256..512u64 {
            let e = self.read_u64(self.kernel_pml4 + i * 8);
            if e != 0 {
                self.write_u64(pml4 + i * 8, e);
            }
        }
        self.make_self_referential(pml4);
        pml4
    }

    /// Map one 4 KiB page, creating whatever intermediate tables are missing.
    pub fn map(&mut self, pml4: u64, va: u64, pa: u64) {
        let mut table = pml4;
        for shift in [39u32, 30, 21] {
            let slot = table + ((va >> shift) & 0x1ff) * 8;
            let entry = self.read_u64(slot);
            table = if entry & 1 != 0 {
                entry & PFN_MASK
            } else {
                let fresh = self.alloc_page();
                self.write_u64(slot, fresh | PRESENT_WRITE);
                fresh
            };
        }
        let slot = table + ((va >> 12) & 0x1ff) * 8;
        self.write_u64(slot, (pa & PFN_MASK) | PRESENT_WRITE);
    }

    /// Map a page into every address space that exists, as the kernel half is.
    fn map_kernel(&mut self, va: u64, pa: u64) {
        let pml4 = self.kernel_pml4;
        self.map(pml4, va, pa);
    }

    /// A `UNICODE_STRING` plus its buffer, written into an address space.
    fn write_unicode(&mut self, pml4: u64, struct_va: u64, struct_pa: u64, text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
        assert!(bytes.len() < PAGE as usize, "test strings stay within one page");

        let buf_pa = self.alloc_page();
        let buf_va = struct_va & !(PAGE - 1);
        // Park the buffer a fixed distance away so each string gets its own page
        // without the test having to manage a user-space allocator.
        let buf_va = buf_va + 0x10_0000 + (buf_pa & 0xfff_000) % 0x40_0000;
        self.map(pml4, buf_va, buf_pa);
        self.write(buf_pa, &bytes);

        self.write_u16(struct_pa, bytes.len() as u16);
        self.write_u16(struct_pa + 2, bytes.len() as u16 + 2);
        self.write_u64(struct_pa + 8, buf_va);
    }

    /// Build the user-mode side of a process and return its PEB address.
    fn build_peb(&mut self, pml4: u64, spec: &ProcessSpec, index: u64) -> u64 {
        let base_va = USER_VA_BASE + index * 0x100_0000;

        let peb_pa = self.alloc_page();
        let peb_va = base_va;
        self.map(pml4, peb_va, peb_pa);

        let params_pa = self.alloc_page();
        let params_va = base_va + PAGE;
        self.map(pml4, params_va, params_pa);
        self.write_u64(peb_pa + user::PEB_PROCESS_PARAMETERS, params_va);

        if let Some(cmd) = spec.command_line {
            self.write_unicode(pml4, params_va + user::PARAMS_COMMAND_LINE, params_pa + user::PARAMS_COMMAND_LINE, cmd);
        }
        if let Some(path) = spec.image_path {
            self.write_unicode(pml4, params_va + user::PARAMS_IMAGE_PATH, params_pa + user::PARAMS_IMAGE_PATH, path);
        }
        self.write_unicode(
            pml4,
            params_va + user::PARAMS_CURRENT_DIRECTORY,
            params_pa + user::PARAMS_CURRENT_DIRECTORY,
            "C:\\Windows\\system32\\",
        );

        if !spec.modules.is_empty() {
            let ldr_pa = self.alloc_page();
            let ldr_va = base_va + 2 * PAGE;
            self.map(pml4, ldr_va, ldr_pa);
            self.write_u64(peb_pa + user::PEB_LDR, ldr_va);

            let head_va = ldr_va + user::LDR_IN_LOAD_ORDER;
            let mut entries = Vec::new();
            for (i, _) in spec.modules.iter().enumerate() {
                let pa = self.alloc_page();
                let va = base_va + (3 + i as u64) * PAGE;
                self.map(pml4, va, pa);
                entries.push((va, pa));
            }
            self.write_u64(ldr_pa + user::LDR_IN_LOAD_ORDER, entries[0].0);

            for (i, &(name, dll_base, size)) in spec.modules.iter().enumerate() {
                let (va, pa) = entries[i];
                let next = entries.get(i + 1).map(|e| e.0).unwrap_or(head_va);
                self.write_u64(pa, next);
                self.write_u64(pa + ENTRY_BLINK, head_va);
                self.write_u64(pa + user::ENTRY_DLL_BASE, dll_base);
                self.write_u32(pa + user::ENTRY_SIZE_OF_IMAGE, size);
                self.write_unicode(pml4, va + user::ENTRY_FULL_NAME, pa + user::ENTRY_FULL_NAME, name);
            }
        }

        peb_va
    }

    /// Place all the processes, wire the linked ones into a ring, and finish.
    pub fn build(self, specs: &[ProcessSpec]) -> PhysicalMemory {
        PhysicalMemory::raw_from_bytes(self.build_bytes(specs))
    }

    /// As `build`, but hands back the bytes, for tests that need a file on disk.
    pub fn build_bytes(mut self, specs: &[ProcessSpec]) -> Vec<u8> {
        // Every process gets a pool allocation, page-aligned so the header sits
        // at the start of a page and the structure never straddles one.
        let mut placed = Vec::new();
        for (i, spec) in specs.iter().enumerate() {
            let page = self.alloc_page();
            let body_pa = page + 0x10;
            let block_size = (layout::SIZE + 0x10) / 0x10;
            self.write_u32(page, ((block_size as u32) << 16) | 0x0001);
            self.write(page + 0x0c, b"Proc");

            let pml4 = if spec.command_line.is_some() || !spec.modules.is_empty() {
                self.new_address_space()
            } else {
                self.kernel_pml4
            };

            self.write_u64(body_pa + layout::DTB, pml4);
            self.write_u64(body_pa + layout::UNIQUE_PROCESS_ID, spec.pid);
            self.write_u64(body_pa + layout::INHERITED_FROM_PID, spec.ppid);
            self.write_u64(body_pa + layout::CREATE_TIME, spec.create_time);
            self.write_u64(body_pa + layout::EXIT_TIME, spec.exit_time);

            let mut name = [0u8; 15];
            let src = spec.name.as_bytes();
            name[..src.len()].copy_from_slice(src);
            self.write(body_pa + layout::IMAGE_FILE_NAME, &name);

            if spec.command_line.is_some() || !spec.modules.is_empty() {
                let peb_va = self.build_peb(pml4, spec, i as u64);
                self.write_u64(body_pa + layout::PEB, peb_va);
            }

            let va = self.reserve_kernel_va(1);
            self.map_kernel(va, page);
            placed.push((body_pa, va + 0x10, spec.linked));
        }

        // `PsActiveProcessHead` is a bare list entry in kernel data, part of the
        // ring but not part of any process. Including it is what makes the test
        // exercise the tolerance the real thing needs.
        let head_page = self.alloc_page();
        let head_va = self.reserve_kernel_va(1) + 0x200;
        self.map_kernel(head_va & !(PAGE - 1), head_page);
        let head_entry_pa = head_page + (head_va & 0xfff);

        let mut ring: Vec<(u64, u64)> = vec![(head_entry_pa, head_va)];
        for &(body_pa, va, linked) in &placed {
            if linked {
                ring.push((body_pa + layout::ACTIVE_PROCESS_LINKS, va + layout::ACTIVE_PROCESS_LINKS));
            }
        }
        for i in 0..ring.len() {
            let (pa, _) = ring[i];
            let next = ring[(i + 1) % ring.len()].1;
            let prev = ring[(i + ring.len() - 1) % ring.len()].1;
            self.write_u64(pa, next);
            self.write_u64(pa + 8, prev);
        }

        self.bytes
    }
}

const ENTRY_BLINK: u64 = 0x08;
