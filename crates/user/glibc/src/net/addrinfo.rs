// addrinfo — getaddrinfo/getnameinfo (docs/59§6 G13). Numeric + localhost
// resolution (hosted-testable, no DNS): a node parsed by inet_pton, or
// "localhost"/NULL → loopback. /etc/hosts parsing + a stub DNS resolver (UDP
// to the /etc/resolv.conf nameserver) are a follow-up. The address builder is
// pure + hosted-tested; getaddrinfo (which malloc's the result chain) is the
// freestanding C export.
#![allow(clippy::upper_case_acronyms)]
use super::inet;
use super::socket::{AF_INET, AF_INET6};

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
pub const EAI_FAMILY: i32 = -6;
pub const EAI_SERVICE: i32 = -8;
pub const EAI_MEMORY: i32 = -10;
pub const EAI_SYSTEM: i32 = -11;

/// Parse a service string to a port. Numeric ("80") or a small well-known
/// table (DNS resolution of /etc/services is a follow-up). None on bad.
pub(crate) fn parse_port(service: &[u8]) -> Option<u16> {
    if service.is_empty() { return Some(0); }
    if service.iter().all(|b| b.is_ascii_digit()) {
        let mut v: u32 = 0;
        for &b in service { v = v * 10 + (b - b'0') as u32; if v > 65535 { return None; } }
        return Some(v as u16);
    }
    match service {
        b"http" => Some(80),
        b"https" => Some(443),
        b"domain" => Some(53),
        b"ssh" => Some(22),
        _ => None,
    }
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

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::malloc::heap;
    use crate::string::len::strlen_impl;

    unsafe fn slice_or_empty<'a>(p: *const u8) -> &'a [u8] {
        // SAFETY: p is null or a NUL-terminated C string.
        unsafe { if p.is_null() { &[] } else { core::slice::from_raw_parts(p, strlen_impl(p)) } }
    }

    // # C: int getaddrinfo(const char *node, const char *service,
    //                      const struct addrinfo *hints, struct addrinfo **res)
    #[no_mangle]
    pub unsafe extern "C" fn getaddrinfo(node: *const u8, service: *const u8, hints: *const addrinfo, res: *mut *mut addrinfo) -> i32 {
        // SAFETY: node/service null or C strings; hints null or a valid
        // addrinfo; res a writable out-param. We build one numeric result.
        unsafe {
            let want = if hints.is_null() { 0 } else { (*hints).ai_family };
            let flags = if hints.is_null() { 0 } else { (*hints).ai_flags };
            let socktype = if hints.is_null() { 0 } else { (*hints).ai_socktype };
            let port = match parse_port(slice_or_empty(service)) { Some(p) => p, None => return EAI_SERVICE };
            let n = slice_or_empty(node);
            // non-numeric, non-localhost host without DNS is unresolvable here.
            let (fam, bytes, len) = match fill_sockaddr(n, port, want) {
                Some(t) => t,
                None => return EAI_NONAME,
            };
            let _ = flags;
            let sa = heap::malloc(len as usize);
            let ai = heap::malloc(core::mem::size_of::<addrinfo>()) as *mut addrinfo;
            if sa.is_null() || ai.is_null() { return EAI_MEMORY; }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), sa, len as usize);
            (*ai).ai_flags = 0;
            (*ai).ai_family = fam;
            (*ai).ai_socktype = if socktype != 0 { socktype } else { 1 };
            (*ai).ai_protocol = 0;
            (*ai).ai_addrlen = len;
            (*ai).__pad = 0;
            (*ai).ai_addr = sa as *mut core::ffi::c_void;
            (*ai).ai_canonname = core::ptr::null_mut();
            (*ai).ai_next = core::ptr::null_mut();
            *res = ai;
            0
        }
    }

    // # C: void freeaddrinfo(struct addrinfo *res)
    #[no_mangle]
    pub unsafe extern "C" fn freeaddrinfo(mut res: *mut addrinfo) {
        // SAFETY: res is a chain from getaddrinfo; free each node + its addr.
        unsafe {
            while !res.is_null() {
                let next = (*res).ai_next;
                if !(*res).ai_addr.is_null() { heap::free((*res).ai_addr as *mut u8); }
                if !(*res).ai_canonname.is_null() { heap::free((*res).ai_canonname); }
                heap::free(res as *mut u8);
                res = next;
            }
        }
    }

    // # C: const char *gai_strerror(int ecode)
    #[no_mangle]
    pub extern "C" fn gai_strerror(ecode: i32) -> *const u8 {
        let s: &[u8] = match ecode {
            0 => b"Success\0",
            EAI_BADFLAGS => b"Bad value for ai_flags\0",
            EAI_NONAME => b"Name or service not known\0",
            EAI_AGAIN => b"Temporary failure in name resolution\0",
            EAI_FAIL => b"Non-recoverable failure in name resolution\0",
            EAI_FAMILY => b"ai_family not supported\0",
            EAI_SERVICE => b"Servname not supported for ai_socktype\0",
            EAI_MEMORY => b"Memory allocation failure\0",
            EAI_SYSTEM => b"System error\0",
            _ => b"Unknown error\0",
        };
        s.as_ptr()
    }

    // # C: int getnameinfo(const struct sockaddr *sa, socklen_t salen,
    //                      char *host, socklen_t hostlen, char *serv,
    //                      socklen_t servlen, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn getnameinfo(sa: *const u8, _salen: u32, host: *mut u8, hostlen: u32, serv: *mut u8, servlen: u32, _flags: i32) -> i32 {
        // SAFETY: sa is a sockaddr (family in the first u16); host/serv are
        // writable for their lengths. Numeric reverse only.
        unsafe {
            if sa.is_null() { return EAI_FAIL; }
            let fam = u16::from_le_bytes([*sa, *sa.add(1)]);
            let port_be = u16::from_be_bytes([*sa.add(2), *sa.add(3)]);
            if !host.is_null() && hostlen > 0 {
                let mut buf = [0u8; super::inet::INET6_ADDRSTRLEN];
                let n = if fam == AF_INET {
                    let mut a = [0u8; 4]; core::ptr::copy_nonoverlapping(sa.add(4), a.as_mut_ptr(), 4);
                    inet::ntop4(&a, &mut buf)
                } else if fam == AF_INET6 {
                    let mut a = [0u8; 16]; core::ptr::copy_nonoverlapping(sa.add(8), a.as_mut_ptr(), 16);
                    inet::ntop6(&a, &mut buf)
                } else { return EAI_FAMILY };
                match n {
                    Some(len) if (len as u32) < hostlen => { core::ptr::copy_nonoverlapping(buf.as_ptr(), host, len); *host.add(len) = 0; }
                    _ => return EAI_SYSTEM,
                }
            }
            if !serv.is_null() && servlen > 0 {
                let mut tmp = [0u8; 8];
                let mut v = port_be as u32;
                let mut k = 0;
                if v == 0 { tmp[0] = b'0'; k = 1; } else { while v > 0 { tmp[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; } }
                if (k as u32) >= servlen { return EAI_SYSTEM; }
                for j in 0..k { *serv.add(j) = tmp[k - 1 - j]; }
                *serv.add(k) = 0;
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_parsing() {
        assert_eq!(parse_port(b"80"), Some(80));
        assert_eq!(parse_port(b""), Some(0));
        assert_eq!(parse_port(b"https"), Some(443));
        assert_eq!(parse_port(b"99999"), None);
        assert_eq!(parse_port(b"nope"), None);
    }

    #[test]
    fn numeric_v4() {
        let (fam, b, len) = fill_sockaddr(b"127.0.0.1", 80, 0).unwrap();
        assert_eq!(fam, AF_INET as i32);
        assert_eq!(len, 16);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), AF_INET); // family
        assert_eq!([b[2], b[3]], 80u16.to_be_bytes()); // port BE
        assert_eq!([b[4], b[5], b[6], b[7]], [127, 0, 0, 1]); // addr network order
    }

    #[test]
    fn numeric_v6_and_localhost() {
        let (fam, b, len) = fill_sockaddr(b"::1", 443, 0).unwrap();
        assert_eq!(fam, AF_INET6 as i32);
        assert_eq!(len, 28);
        assert_eq!([b[2], b[3]], 443u16.to_be_bytes());
        assert_eq!(b[8..24], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // localhost → v4 loopback when family unspecified
        let (fam2, b2, _) = fill_sockaddr(b"localhost", 22, 0).unwrap();
        assert_eq!(fam2, AF_INET as i32);
        assert_eq!([b2[4], b2[5], b2[6], b2[7]], [127, 0, 0, 1]);
        // unresolvable name without DNS
        assert!(fill_sockaddr(b"example.com", 80, 0).is_none());
    }
}
