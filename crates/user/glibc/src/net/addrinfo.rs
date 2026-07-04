// addrinfo — getaddrinfo/getnameinfo (docs/59§6 G13). Numeric + localhost
// resolution: a node parsed by inet_pton, /etc/hosts, DNS via the
// /etc/resolv.conf nameserver, or "localhost"/NULL → loopback. The address
// builders and DNS answer parser are pure + hosted-tested; getaddrinfo (which
// malloc's the result chain) is the freestanding C export.
#![allow(clippy::upper_case_acronyms)]
use super::inet;
use super::netdb;
use super::socket::{AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM};

pub const AI_PASSIVE: i32 = 1;
pub const AI_CANONNAME: i32 = 2;
pub const AI_NUMERICHOST: i32 = 4;
pub const AI_NUMERICSERV: i32 = 1024;
pub const NI_NUMERICHOST: i32 = 1;
pub const NI_NUMERICSERV: i32 = 2;

pub const EAI_BADFLAGS: i32 = -1;
pub const EAI_NONAME: i32 = -2;
pub const EAI_AGAIN: i32 = -3;
pub const EAI_FAIL: i32 = -4;
pub const EAI_NODATA: i32 = -5;
pub const EAI_FAMILY: i32 = -6;
pub const EAI_SOCKTYPE: i32 = -7;
pub const EAI_SERVICE: i32 = -8;
pub const EAI_ADDRFAMILY: i32 = -9;
pub const EAI_MEMORY: i32 = -10;
pub const EAI_SYSTEM: i32 = -11;
pub const EAI_OVERFLOW: i32 = -12;
pub const EAI_INPROGRESS: i32 = -100;
pub const EAI_CANCELED: i32 = -101;
pub const EAI_NOTCANCELED: i32 = -102;
pub const EAI_ALLDONE: i32 = -103;
pub const EAI_INTR: i32 = -104;
pub const EAI_IDN_ENCODE: i32 = -105;
const GAI_WAIT: i32 = 0;
const GAI_NOWAIT: i32 = 1;
const EINVAL: i32 = 22;
const C_IN: u16 = 1;
const T_A: u16 = 1;
const T_AAAA: u16 = 28;

fn proto_matches_socktype(proto: &str, socktype: i32) -> bool {
    match socktype {
        0 => true,
        SOCK_STREAM => proto == "tcp",
        SOCK_DGRAM => proto == "udp",
        _ => false,
    }
}

fn parse_numeric_port(service: &[u8]) -> Option<u16> {
    if service.iter().all(|b| b.is_ascii_digit()) {
        let mut v: u32 = 0;
        for &b in service {
            v = v * 10 + (b - b'0') as u32;
            if v > 65535 {
                return None;
            }
        }
        return Some(v as u16);
    }
    None
}

fn parse_builtin_port(service: &[u8], socktype: i32) -> Option<u16> {
    let (port, proto) = match service {
        b"http" => (80, "tcp"),
        b"https" => (443, "tcp"),
        b"domain" if socktype == SOCK_DGRAM => (53, "udp"),
        b"domain" => (53, "tcp"),
        b"ssh" => (22, "tcp"),
        _ => return None,
    };
    proto_matches_socktype(proto, socktype).then_some(port)
}

/// Parse a service string to a port. Numeric ("80"), /etc/services content,
/// or the small well-known fallback table used when /etc/services is absent.
/// # C: in_port_t parse_port(const char *service) — getservbyname helper
pub(crate) fn parse_port(service: &[u8]) -> Option<u16> {
    parse_port_with_services(service, 0, &[])
}

/// # C: getaddrinfo service lookup using /etc/services and ai_socktype proto.
pub(crate) fn parse_port_with_services(service: &[u8], socktype: i32, services: &[u8]) -> Option<u16> {
    if service.is_empty() { return Some(0); }
    if let Some(port) = parse_numeric_port(service) {
        return Some(port);
    }

    let text = core::str::from_utf8(services).unwrap_or("");
    for line in text.lines() {
        if let Some(v) = netdb::parse_serv_line(line) {
            let name_matches = v.name.as_bytes() == service || v.aliases.iter().any(|a| a.as_bytes() == service);
            if name_matches && proto_matches_socktype(&v.proto, socktype) {
                return Some(v.port);
            }
        }
    }

    services.is_empty().then(|| parse_builtin_port(service, socktype)).flatten()
}

/// Build a sockaddr (in/in6) for a numeric `node` + `port`, honoring a family
/// hint (AF_UNSPEC=0 tries v4 then v6). Returns (family, 28-byte buffer, len).
/// `node` "localhost" / empty maps to loopback.
///
/// # C: numeric node+port → sockaddr_in/in6 bytes
pub(crate) fn fill_sockaddr(node: &[u8], port: u16, want: i32) -> Option<(i32, [u8; 28], u32)> {
    // map localhost / empty to a loopback literal per family preference
    let v4lit: &[u8] = b"127.0.0.1";
    let v6lit: &[u8] = b"::1";
    let is_local = node.is_empty() || node == b"localhost";
    let mut b = [0u8; 28];

    if want == AF_INET as i32 || want == 0 {
        let src = if is_local { v4lit } else { node };
        let mut a = [0u8; 4];
        if inet::pton4(src, &mut a) {
            b[0..2].copy_from_slice(&AF_INET.to_le_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[4..8].copy_from_slice(&a);
            return Some((AF_INET as i32, b, 16));
        }
    }
    if want == AF_INET6 as i32 || want == 0 {
        let src = if is_local { v6lit } else { node };
        let mut a = [0u8; 16];
        if inet::pton6(src, &mut a) {
            b[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[8..24].copy_from_slice(&a);
            return Some((AF_INET6 as i32, b, 28));
        }
    }
    None
}

fn fill_sockaddr_from_host(h: &netdb::HostVal, port: u16, want: i32) -> Option<(i32, [u8; 28], u32)> {
    if want != 0 && h.addrtype != want { return None; }
    let mut b = [0u8; 28];
    if h.addrtype == AF_INET as i32 && h.addrlen == 4 {
        b[0..2].copy_from_slice(&AF_INET.to_le_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&h.addr[..4]);
        return Some((AF_INET as i32, b, 16));
    }
    if h.addrtype == AF_INET6 as i32 && h.addrlen == 16 {
        b[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[8..24].copy_from_slice(&h.addr[..16]);
        return Some((AF_INET6 as i32, b, 28));
    }
    None
}

/// # C: /etc/hosts bytes + name/service → sockaddr_in/in6 bytes
pub(crate) fn fill_sockaddr_from_hosts(
    hosts: &[u8],
    node: &[u8],
    port: u16,
    want: i32,
) -> Option<(i32, [u8; 28], u32)> {
    if node.is_empty() { return None; }
    let text = core::str::from_utf8(hosts).ok()?;
    text.lines()
        .filter_map(netdb::parse_host_line)
        .filter(|h| h.name.as_bytes() == node || h.aliases.iter().any(|a| a.as_bytes() == node))
        .find_map(|h| fill_sockaddr_from_host(&h, port, want))
}

fn skip_dns_name(msg: &[u8], mut off: usize) -> Option<usize> {
    let mut hops = 0usize;
    loop {
        let b = *msg.get(off)?;
        off += 1;
        match b & 0xc0 {
            0 => {
                if b == 0 {
                    return Some(off);
                }
                off = off.checked_add(b as usize)?;
                if off > msg.len() {
                    return None;
                }
            }
            0xc0 => {
                msg.get(off)?;
                return Some(off + 1);
            }
            _ => return None,
        }
        hops += 1;
        if hops > 128 {
            return None;
        }
    }
}

fn be16(msg: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(off)?, *msg.get(off + 1)?]))
}

/// # C: DNS response bytes + requested family → sockaddr_in/in6 bytes
pub(crate) fn fill_sockaddr_from_dns(answer: &[u8], port: u16, want: i32) -> Option<(i32, [u8; 28], u32)> {
    if answer.len() < 12 {
        return None;
    }
    let qd = be16(answer, 4)? as usize;
    let an = be16(answer, 6)? as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_dns_name(answer, off)?;
        off = off.checked_add(4)?;
        if off > answer.len() {
            return None;
        }
    }
    for _ in 0..an {
        off = skip_dns_name(answer, off)?;
        let ty = be16(answer, off)?;
        let class = be16(answer, off + 2)?;
        let rdlen = be16(answer, off + 8)? as usize;
        off = off.checked_add(10)?;
        let rdata_end = off.checked_add(rdlen)?;
        if rdata_end > answer.len() {
            return None;
        }
        if class == C_IN && ty == T_A && rdlen == 4 && (want == 0 || want == AF_INET as i32) {
            let mut b = [0u8; 28];
            b[0..2].copy_from_slice(&AF_INET.to_le_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[4..8].copy_from_slice(&answer[off..off + 4]);
            return Some((AF_INET as i32, b, 16));
        }
        if class == C_IN && ty == T_AAAA && rdlen == 16 && (want == 0 || want == AF_INET6 as i32) {
            let mut b = [0u8; 28];
            b[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
            b[2..4].copy_from_slice(&port.to_be_bytes());
            b[8..24].copy_from_slice(&answer[off..off + 16]);
            return Some((AF_INET6 as i32, b, 28));
        }
        off = rdata_end;
    }
    None
}

#[repr(C)]
pub struct addrinfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: u32,
    __pad: u32,
    pub ai_addr: *mut core::ffi::c_void,
    pub ai_canonname: *mut u8,
    pub ai_next: *mut addrinfo,
}
const _: () = assert!(core::mem::size_of::<addrinfo>() == 48);

#[repr(C)]
pub struct gaicb {
    pub ar_name: *const u8,
    pub ar_service: *const u8,
    pub ar_request: *const addrinfo,
    pub ar_result: *mut addrinfo,
    pub __return: i32,
    __glibc_reserved: [i32; 5],
}
const _: () = assert!(core::mem::size_of::<gaicb>() == 56);

#[cfg(feature = "freestanding")]

// Module manifest: exports owns C ABI allocation wrappers; tests owns resolver helpers.
#[cfg(feature = "freestanding")]
mod exports;
#[cfg(feature = "freestanding")]
pub use exports::*;
#[cfg(test)]
mod tests;
