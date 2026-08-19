# Artifacts you can investigate

Catalog of what actually lands in a live or memory case today: entity kind, event kind, where it was read, and how to look at it. If something is listed in [usage.md](usage.md#not-collected-yet) as *not collected*, absence in the viewer means the collector did not ask for it — not that it was missing on the host.

Operator path (USB collect, viewer, flags): **[usage.md](usage.md)**.

Timestamps: process creation uses the OS creation time. Everything else from a live snapshot (sockets, services, drivers, autoruns, module *observations*) is placed at collection time and marked **inferred**. Filter **suspect time** to see only those. Do not treat inferred events as "this happened at collection second".

### Host identity

**When:** live collect (first). Memory cases leave hostname as the image filename; they do not invent the examiner's hostname.

| Field | Source |
|---|---|
| Hostname, DNS domain | `GetComputerNameExW` |
| OS name / version | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| Native architecture | `GetNativeSystemInfo` |
| `MachineGuid` | `HKLM\SOFTWARE\Microsoft\Cryptography` |
| Time zone name, UTC bias (minutes) | `GetTimeZoneInformation` |
| Wall clock | `GetSystemTimePreciseAsFileTime` |
| Uptime / derived boot time | `GetTickCount64` |

**Investigate:** inspector with no selection (Case). `tpv info` prints the same block. Use timezone bias when converting any later local-time artifact; use `MachineGuid` to correlate with other collections from the same box.

### Collector custody

**When:** every finalized case.

| Field | Why it matters |
|---|---|
| Collector PID, image path, SHA-256 of `tpv.exe` | Subtract the tool from the process tree; confirm *this* binary produced the case |
| Command line | Records `--allow-local-write` and other flags |
| Run-as user, elevated | Interprets `access_error` on protected processes |
| Files written | Should be only the case on external media |
| Warnings | Partial enumerations, hidden processes (memory), layout agreement &lt; 90% |

**Investigate:** Case inspector; `tpv info`. Compare `collector_sha256` with the hash printed by `bin\install.ps1`. If they differ, it was not this build.

Manifest path for live state: `live://windows/volatile-state`, method `live_api`. Failed or partial acquisition is stored as `error` on that entry — a gap, not a silent skip.

### Processes (live)

**Entity:** `process` — identity is PID **plus** creation time (`proc:<pid>:<utc_ns>`). A recycled PID is a different node. If creation time is unknown, the key is `proc:<pid>:unknown` and parent links are best-effort.

**Event:** `process_snapshot` (source `live`). Timestamp is process create time, not collection time. Payload also stores `observed_utc_ns`.

Read via Toolhelp snapshot, then per-process `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`. Command line uses `NtQueryInformationProcess` class 60 (no VM read). Modules need `PROCESS_VM_READ`.

| Attribute | Notes |
|---|---|
| `name` | Toolhelp base name — always present, even if the process could not be opened |
| `image_path` | Full path when query succeeded |
| `image_sha256` | SHA-256 of the on-disk image when readable; access denied is a gap, not an abort |
| `command_line` | Often the highest-value field; missing when access failed |
| `user` / SID | Token user |
| `elevated` | Token elevation |
| `wow64` | 32-bit process on 64-bit Windows |
| `session_id` | RDP / console session |
| `thread_count`, `handle_count` | Snapshot counts |
| `module_count` | How many modules were readable |
| `access_error` | Why the process was only partially inspected |

**Edges:** `parent_of` (dropped if the "parent" was created *after* the child — recycled PID), `executed_image` → file, `loaded_module` → module, `connected_to` → socket, `hosts_service` from a running service.

**Investigate:**

1. Tree: odd parents (`cmd.exe` → `powershell` → unknown image), unsigned-looking paths under `Temp` / `AppData`, elevation mismatches.
2. Pin the process; scan its events for `net_connection` and `module_load`.
3. Inspector: command line, image path, `access_error`. Right-click → copy command line into the report.
4. `tpv tree case.tpv` on a console when the viewer is not available.

Tree labels are the **base name**, not the full path, so privilege differences do not reshape the forest. Full path lives on the entity and on events.

### Image files

**Entity:** `file`, key = normalized path (`\??\` and `\\?\` stripped, lowercased). Same binary seen as a process image and as a module collapses to one node.

**Investigate:** click the file in inspector relations (`executed_image` / path on events). Live collect hashes unique process image paths (SHA-256) unless `--no-disk`. Hunt a hash by pasting it into the IOC box.

### Prefetch

**When:** live collect, after the volatile snapshot and before EVTX (unless `--no-disk`).

**Entity:** `file`. **Event:** `execution_evidence` (source `prefetch`). Run count and mapped filenames sit in the payload. Last-run time is used when the parser exposes it; otherwise the event is marked inferred at collection time.

**Investigate:** filter source `prefetch`, or hunt an executable name. Absence after `--no-disk` means "not requested".

### Scheduled tasks

**When:** live collect, after Prefetch (unless `--no-disk`). Walk of `C:\Windows\System32\Tasks` XML (name, command, author). Not a WMI dump.

**Entity:** `scheduled_task`. **Event:** `task_register` (source `scheduled_tasks`), inferred timestamp.

**Investigate:** source chip `scheduled_tasks`, or search a command path. Event log 4698 still appears under `evtx` when that channel was collected.

### Loaded modules (live)

**Entity:** `module`. **Event:** `module_load` (inferred timestamp — load time is not in the snapshot).

Payload: `base`, `size`, path. Requires VM-read access; protected processes have none.

**Investigate:** pin the process, search the event table for unexpected DLLs (`AppData`, `Temp`, unsigned-looking names next to `System32`). Compare module path with the process image path.

### Network endpoints

**Entity:** `net_endpoint`. **Events:** `net_connection` vs `net_listen` (source `live`).

API: `GetExtendedTcpTable` / `GetExtendedUdpTable` OWNER_PID, IPv4 and IPv6.

| Field | Notes |
|---|---|
| `proto` | `tcp`, `tcp6`, `udp`, `udp6` |
| `local` / `remote` | `ip:port`; IPv6 as `[addr]:port` |
| `state` | TCP state (`established`, `listen`, `time_wait`, …) |
| Owner PID | 0 = kernel / no usermode owner |

Listeners (no peer, or state `listen`) are a separate event kind so they do not look like outbound beacons.

**Investigate:** filter chip **network**; or pin a process and read its `connected_to` relations. Look for:

- established TCP to unexpected remotes
- listeners on high ports owned by user processes
- sockets whose PID is missing from the process list (process exited between the two enumerations — still recorded)

### Windows services

**Entity:** `service`. **Event:** `service_state` (source `services`). Inferred timestamp.

SCM: `EnumServicesStatusExW` + `QueryServiceConfigW`.

| Attribute | Notes |
|---|---|
| `name` / display name | Service key vs friendly name |
| `state` | `running`, `stopped`, … |
| `start_type` | `boot`, `system`, `auto`, `demand`, `disabled` |
| `service_type` | `own_process`, `share_process`, drivers mixed in type flags |
| `binary_path` | Configured command line — may disagree with the live process image |
| `account` | Service logon account |
| PID | When running; linked with `hosts_service` |

**Investigate:** search event summaries for `service `. Compare `binary_path` (unquoted paths with spaces, `cmd.exe /c`, Temp) with the hosted process's `image_path` and command line. A running service whose binary path does not match the process image is a finding-shaped disagreement, not a parser error.

### Kernel drivers

**Entity:** `driver`. **Event:** `driver_load` (source `live`). Inferred timestamp.

API: `EnumDeviceDrivers` + `GetDeviceDriverFileNameW`. Payload: `base`, `path`.

**Investigate:** search `driver_load` / kernel module names. Unusual paths outside `\Windows\System32\drivers`. This is the *loaded* set, not the service-start configuration (that lives under services when type is a driver).

### Autostart (Run keys)

**Entity:** `registry_key`. **Event:** `autostart_entry` (source `registry`). Inferred timestamp — configuration observed now, not the last time it ran.

Live registry API, HKLM and HKCU, 64-bit view:

- `Software\Microsoft\Windows\CurrentVersion\Run`
- `RunOnce`, `RunServices`, `RunServicesOnce`
- `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `Software\Microsoft\Windows NT\CurrentVersion\Windows`

Payload: `hive`, `key`, `value_name`, `value` (command). This is a **small, well-understood subset**, not Sysinternals Autoruns.

**Investigate:** filter source chip `registry`, or search the value command. Follow the path to a process if that image is still running.

### Windows event logs

**When:** live collect, unless `--no-evtx`. After the volatile snapshot. Source `evtx`. Method `win32_file` (the live `.evtx` — last-access on those files may update).

High-value channels, each hashed and listed on the manifest:

| Channel | File | Required |
|---|---|---|
| Security | `Security.evtx` | yes — missing/denied is a gap |
| System | `System.evtx` | yes |
| Application | `Application.evtx` | yes |
| Windows PowerShell | `Windows PowerShell.evtx` | skip if absent |
| PowerShell Operational | `Microsoft-Windows-PowerShell%4Operational.evtx` | skip if absent |
| Sysmon Operational | `Microsoft-Windows-Sysmon%4Operational.evtx` | skip if absent |
| Defender Operational | `Microsoft-Windows-Windows Defender%4Operational.evtx` | skip if absent |
| RDP LocalSessionManager | `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` | skip if absent |
| Task Scheduler Operational | `Microsoft-Windows-TaskScheduler%4Operational.evtx` | skip if absent |

Each channel is ingested in full. A huge Security log can take minutes and produce a large case; `--evtx-cap 25000` restores the old triage limit. Access denied on Security is a gap, not a crash.

Event ids that already have a kind in the model are mapped; the rest stay `log_record`. Channel name is stored in `path` so the Logs tab can filter it as a column.

| Event | Kind |
|---|---|
| 4688 / Sysmon 1 | `process_start` |
| 4689 / Sysmon 5 | `process_end` |
| 4624, 4625, 4634, 4647, 4648, 4778, 4779 / RDP 21–25 | `logon_session` |
| 7045 | `service_install` |
| 7034–7036, 7040 | `service_state` |
| 4698 / 106 | `task_register` |
| Sysmon 3 | `net_connection` |
| Sysmon 6 | `driver_load` |
| Sysmon 11 | `file_create` |
| Sysmon 13 | `registry_write` |
| everything else | `log_record` |

Historical process-create events carry a PID but not the live process's creation-time entity key. Pinning a live process still shows those rows: the filter matches the PID as well as the entity.

**Investigate:**

1. Open the **Logs** tab. Filter the Event ID column (`4688`, `1`) or Channel (`Security`, `Sysmon`). Kind (`process_start`, `logon_session`).
2. Search box understands prefixes: `id:4688`, `id:4688,4624`, `pid:1234`, `user:alice`, `channel:Sysmon`. A bare number matches Event ID or PID.
3. Right-click a 4688 → **Pin PID in the tree**, then read the live command line next to the log start.
4. A missing Sysmon channel with no gap means Sysmon was not installed, not that the collector failed.

### Users

The live collector records the **process token user** on each process (`user`, SID). It does not yet emit a separate `user` entity or `owned_by_user` edges. Pivot by searching the process inspector / event payload for the account string.

### Memory-image processes

**When:** `tpv memory` or open a dump in the viewer. Source `memory`.

Same process / file / module graph as live, plus:

| Attribute | Meaning |
|---|---|
| `discovery` | `process list`, `pool scan only`, or `process list and pool scan` |
| `hidden_from_process_list` | Present in pool, **missing** from `PsActiveProcessHead` — classic unlinked hiding |
| `directory_table_base` | CR3 / DTB |
| `eprocess_physical` | Physical address of `EPROCESS` |
| `peb` | PEB virtual address (needed for command line / modules / cwd) |
| `current_directory` | From PEB |
| `exited` | Exit time non-zero |

**Events:** `process_snapshot`; `process_end` if the EPROCESS had an exit time; `module_load` per mapped image; `collector_action` for kernel-layout calibration (linked-entry count, field agreement %, page-table root).

Unlinked **and still running** is called out in the event summary (`MISSING from the kernel's process list`) and in custody warnings. Unlinked **and exited** is normal pool residue — still listed, wording differs.

If PEB was not recovered, command lines and modules are empty **for the whole case**; custody warns so empty command lines are not mistaken for "the process had none".

Linux images opened the same way (`tpv memory`, or File → Open in the viewer):

| Recovery | When | Confidence |
|---|---|---|
| ELF `NT_PRPSINFO` / `NT_FILE` | Process cores, some crash dumps | High — the kernel wrote the notes |
| `task_struct` scan | LiME / raw Linux RAM, after `kthreadd` teaches the pid-to-comm delta | Heuristic — custody warns; corroborate PIDs |
| Banner only | `Linux version ` found, no process list | OS identified; empty tree is honest |

Host `os_name` is `Linux (recovered from a memory image)`; the banner is stored as `os_version`. Collect does **not** run on Linux hosts.

**Investigate:** search summaries for `pool` / `MISSING`; inspector `discovery` / `hidden_from_process_list`; corroborate parents (unlinked processes still carry PPID). Check calibration agreement; below 90% the layout may be misread. On Linux, read `discovery`: `ELF core notes` vs `Linux task scan`.

Image SHA-256 is on the manifest entry for the dump file.

### Timeline events (cheat sheet)

| Event kind | Typical source | In a live case? | In a memory case? |
|---|---|---|---|
| `process_snapshot` | live / memory | yes | yes |
| `process_end` | memory | no | if EPROCESS has exit time |
| `module_load` | live / memory | yes (inferred) | yes |
| `net_connection` / `net_listen` | live | yes (inferred) | no |
| `service_state` | services | yes (inferred) | no |
| `driver_load` | live | yes (inferred) | no |
| `autostart_entry` | registry | yes (inferred) | no |
| `process_start` / `process_end` | evtx | 4688 / 4689, Sysmon 1 / 5 | no |
| `logon_session` | evtx | 4624 and related | no |
| `log_record` | evtx | unmapped event ids; channel in `path` | no |
| `service_install` | evtx | 7045 | no |
| `collector_action` | collector | custody | calibration / Linux recovery + custody |

---

## Suggested investigation order

  1. **Case inspector** — host, profile (`live_state`, `event_logs`, `disk_artifacts`), custody warnings, integrity badge.
2. **`tpv verify`** — contents still match the sealed digest.
3. **Network chip** — who is talking, which PID, listener vs established.
4. **Process tree** — unexpected lineage, then pin and read command line + modules.
5. **Event logs** — Logs tab; 4688 / Sysmon 1 against the live tree; logons; service installs.
6. **Services + autoruns** — persistence that may outlive the current process list.
7. **Drivers** — unexpected kernel modules.
8. **Memory cases** — anything `pool scan only` with `hidden_from_process_list`; Linux notes vs scan.
9. Copy fields into the report from the context menu; do not retype command lines.

---

