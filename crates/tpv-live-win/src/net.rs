//! TCP and UDP endpoint acquisition, attributed to owning processes.
//!
//! The tables come from `GetExtendedTcpTable` and `GetExtendedUdpTable` in their
//! owner-PID forms, which is what makes a connection attributable at all. All
//! four address families are collected: an implant that beacons over IPv6 on a
//! host where the analyst only looked at IPv4 is invisible for no good reason.

#![allow(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetEndpoint {
    /// `tcp`, `tcp6`, `udp` or `udp6`.
    pub proto: String,
    pub local: String,
    /// Absent for UDP and for listening TCP sockets.
    pub remote: Option<String>,
    pub state: Option<String>,
    pub pid: u32,
}

impl NetEndpoint {
    /// A socket with no peer is a listener, which belongs on a different lane in
    /// the viewer than an established connection.
    pub fn is_listener(&self) -> bool {
        self.remote.is_none() || self.state.as_deref() == Some("listen")
    }
}

/// Decode the network-order address and port fields the MIB tables use.
fn v4(addr: u32, port: u32) -> String {
    let ip = Ipv4Addr::from(addr.to_ne_bytes());
    format!("{ip}:{}", be_port(port))
}

fn v6(addr: &[u8; 16], scope: u32, port: u32) -> String {
    let ip = Ipv6Addr::from(*addr);
    if scope == 0 {
        format!("[{ip}]:{}", be_port(port))
    } else {
        format!("[{ip}%{scope}]:{}", be_port(port))
    }
}

/// Only the low 16 bits of the port field are meaningful, and they are stored in
/// network byte order regardless of host endianness.
fn be_port(port: u32) -> u16 {
    let b = port.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

/// Human-readable TCP state.
fn tcp_state(state: u32) -> &'static str {
    match state {
        1 => "closed",
        2 => "listen",
        3 => "syn_sent",
        4 => "syn_rcvd",
        5 => "established",
        6 => "fin_wait1",
        7 => "fin_wait2",
        8 => "close_wait",
        9 => "closing",
        10 => "last_ack",
        11 => "time_wait",
        12 => "delete_tcb",
        _ => "unknown",
    }
}

/// Fetch a MIB table into a byte buffer, retrying once if it grew between the
/// sizing call and the fetch.
///
/// The retry is not defensive padding: connection tables change while being
/// read, and on a busy host the size genuinely can increase between the two
/// calls. Without the retry the collector would intermittently return nothing.
fn fetch_table(
    mut call: impl FnMut(*mut std::ffi::c_void, &mut u32) -> u32,
) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    call(std::ptr::null_mut(), &mut size);
    if size == 0 {
        return Ok(Vec::new());
    }

    for _ in 0..3 {
        let mut buf = vec![0u8; size as usize];
        let rc = call(buf.as_mut_ptr().cast(), &mut size);
        match rc {
            0 => return Ok(buf),
            // ERROR_INSUFFICIENT_BUFFER: `size` now holds the larger requirement.
            122 => continue,
            other => return Err(format!("MIB table query failed with code {other}")),
        }
    }
    Err("MIB table kept growing across retries".into())
}

pub fn tcp_v4() -> Result<Vec<NetEndpoint>, String> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedTcpTable(
            Some(ptr),
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let rows = unsafe {
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
    };

    Ok(rows
        .iter()
        .map(|r| {
            let listening = r.dwState == 2;
            NetEndpoint {
                proto: "tcp".into(),
                local: v4(r.dwLocalAddr, r.dwLocalPort),
                remote: (!listening).then(|| v4(r.dwRemoteAddr, r.dwRemotePort)),
                state: Some(tcp_state(r.dwState).into()),
                pid: r.dwOwningPid,
            }
        })
        .collect())
}

pub fn tcp_v6() -> Result<Vec<NetEndpoint>, String> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedTcpTable(
            Some(ptr),
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let rows = unsafe {
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
    };

    Ok(rows
        .iter()
        .map(|r| {
            let listening = r.dwState == 2;
            NetEndpoint {
                proto: "tcp6".into(),
                local: v6(&r.ucLocalAddr, r.dwLocalScopeId, r.dwLocalPort),
                remote: (!listening)
                    .then(|| v6(&r.ucRemoteAddr, r.dwRemoteScopeId, r.dwRemotePort)),
                state: Some(tcp_state(r.dwState).into()),
                pid: r.dwOwningPid,
            }
        })
        .collect())
}

pub fn udp_v4() -> Result<Vec<NetEndpoint>, String> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedUdpTable(
            Some(ptr),
            size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let rows = unsafe {
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
    };

    Ok(rows
        .iter()
        .map(|r| NetEndpoint {
            proto: "udp".into(),
            local: v4(r.dwLocalAddr, r.dwLocalPort),
            remote: None,
            state: None,
            pid: r.dwOwningPid,
        })
        .collect())
}

pub fn udp_v6() -> Result<Vec<NetEndpoint>, String> {
    let buf = fetch_table(|ptr, size| unsafe {
        GetExtendedUdpTable(
            Some(ptr),
            size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    })?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let rows = unsafe {
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
    };

    Ok(rows
        .iter()
        .map(|r| NetEndpoint {
            proto: "udp6".into(),
            local: v6(&r.ucLocalAddr, r.dwLocalScopeId, r.dwLocalPort),
            remote: None,
            state: None,
            pid: r.dwOwningPid,
        })
        .collect())
}

/// Every endpoint on the host, across both protocols and both families.
pub fn enumerate() -> (Vec<NetEndpoint>, Vec<String>) {
    let mut all = Vec::new();
    let mut warnings = Vec::new();

    for (label, result) in [
        ("tcp/ipv4", tcp_v4()),
        ("tcp/ipv6", tcp_v6()),
        ("udp/ipv4", udp_v4()),
        ("udp/ipv6", udp_v6()),
    ] {
        match result {
            Ok(mut rows) => all.append(&mut rows),
            // One family failing must not cost the other three.
            Err(e) => warnings.push(format!("{label} enumeration failed: {e}")),
        }
    }
    (all, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_decoding_honours_network_byte_order() {
        // 443 in network order, as the MIB tables store it.
        let stored = u32::from_ne_bytes([0x01, 0xBB, 0, 0]);
        assert_eq!(be_port(stored), 443);
    }

    #[test]
    fn ipv4_addresses_decode_in_memory_order() {
        let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
        let port = u32::from_ne_bytes([0x1F, 0x90, 0, 0]);
        assert_eq!(v4(loopback, port), "127.0.0.1:8080");
    }

    #[test]
    fn ipv6_scope_is_rendered_only_when_present() {
        let mut addr = [0u8; 16];
        addr[15] = 1;
        let port = u32::from_ne_bytes([0x01, 0xBB, 0, 0]);
        assert_eq!(v6(&addr, 0, port), "[::1]:443");
        assert_eq!(v6(&addr, 12, port), "[::1%12]:443");
    }

    #[test]
    fn tcp_states_cover_the_documented_range() {
        assert_eq!(tcp_state(2), "listen");
        assert_eq!(tcp_state(5), "established");
        assert_eq!(tcp_state(99), "unknown");
    }

    #[test]
    fn enumerates_live_endpoints() {
        let (endpoints, warnings) = enumerate();
        assert!(
            warnings.is_empty(),
            "endpoint enumeration should not warn on a healthy host: {warnings:?}"
        );
        assert!(
            !endpoints.is_empty(),
            "a running Windows host always has open sockets"
        );
        // Listeners exist on every Windows host, and they must be attributable.
        assert!(endpoints.iter().any(|e| e.is_listener()));
        assert!(endpoints.iter().any(|e| e.pid != 0));
    }
}
