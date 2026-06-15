//! netdb — `<netdb.h>` host/proto/serv/net/netgroup databases (docs/59§6
//! G13). Backed by /etc/{hosts,protocols,services,networks,netgroup} via the
//! files backend, plus h_errno + the legacy hostent path. struct layouts
//! match host /usr/include/netdb.h (hostent 32, servent 32, protoent 24,
//! netent 24). Non-`_r` use process-global static buffers (glibc's
//! not-thread-safe contract); `_r` pack into the caller buffer + return
//! 0/ERANGE. Pure parsers + packers are hosted-tested; file I/O is
//! freestanding. Split: netdb_proto/serv/host/net + netgr submodules.
#![allow(clippy::upper_case_acronyms)]
extern crate alloc;

// ---- errno + h_errno values (mirror /usr/include/netdb.h) ----
pub(crate) const ENOENT: i32 = 2;
pub(crate) const ERANGE: i32 = 34;
pub(crate) const HOST_NOT_FOUND: i32 = 1;
pub(crate) const TRY_AGAIN: i32 = 2;
pub(crate) const NO_RECOVERY: i32 = 3;
pub(crate) const NO_DATA: i32 = 4;

// ---- C structs (offsets verified against host netdb.h) ----

#[repr(C)]
pub struct hostent {
    pub h_name: *mut u8,
    pub h_aliases: *mut *mut u8,
    pub h_addrtype: i32,
    pub h_length: i32,
    pub h_addr_list: *mut *mut u8,
}
const _: () = assert!(core::mem::size_of::<hostent>() == 32);

#[repr(C)]
pub struct servent {
    pub s_name: *mut u8,
    pub s_aliases: *mut *mut u8,
    pub s_port: i32, // network byte order
    __pad: i32,
    pub s_proto: *mut u8,
}
const _: () = assert!(core::mem::size_of::<servent>() == 32);

#[repr(C)]
pub struct protoent {
    pub p_name: *mut u8,
    pub p_aliases: *mut *mut u8,
    pub p_proto: i32,
    __pad: i32,
}
const _: () = assert!(core::mem::size_of::<protoent>() == 24);

#[repr(C)]
pub struct netent {
    pub n_name: *mut u8,
    pub n_aliases: *mut *mut u8,
    pub n_addrtype: i32,
    pub n_net: u32, // host byte order (classful network number)
}
const _: () = assert!(core::mem::size_of::<netent>() == 24);

// Zero initializers (the `__pad` fields are private; built here).
pub(crate) const ZERO_HOST: hostent = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
pub(crate) const ZERO_SERV: servent = servent { s_name: core::ptr::null_mut(), s_aliases: core::ptr::null_mut(), s_port: 0, __pad: 0, s_proto: core::ptr::null_mut() };
pub(crate) const ZERO_PROTO: protoent = protoent { p_name: core::ptr::null_mut(), p_aliases: core::ptr::null_mut(), p_proto: 0, __pad: 0 };
pub(crate) const ZERO_NET: netent = netent { n_name: core::ptr::null_mut(), n_aliases: core::ptr::null_mut(), n_addrtype: 0, n_net: 0 };

// ---- parsed-line value types (pure side) ----

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtoVal { pub name: String, pub aliases: Vec<String>, pub proto: i32 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServVal { pub name: String, pub aliases: Vec<String>, pub port: u16, pub proto: String }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetVal { pub name: String, pub aliases: Vec<String>, pub net: u32 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostVal { pub name: String, pub aliases: Vec<String>, pub addr: [u8; 16], pub addrtype: i32, pub addrlen: usize }

/// Strip a trailing comment (`#...`), return the payload tokens split on ASCII
/// whitespace. Empty/comment-only lines → empty.
/// # C: tokenize one /etc/{protocols,services,...} line
pub(crate) fn fields(line: &str) -> Vec<&str> {
    let l = match line.split_once('#') { Some((h, _)) => h, None => line };
    l.split_ascii_whitespace().collect()
}

/// # C: parse one /etc/protocols line:  name  number  [aliases...]
pub(crate) fn parse_proto_line(line: &str) -> Option<ProtoVal> {
    let f = fields(line);
    if f.len() < 2 { return None; }
    let proto: i32 = f[1].parse().ok()?;
    Some(ProtoVal { name: f[0].into(), proto, aliases: f[2..].iter().map(|s| (*s).into()).collect() })
}

/// # C: parse one /etc/services line:  name  port/proto  [aliases...]
pub(crate) fn parse_serv_line(line: &str) -> Option<ServVal> {
    let f = fields(line);
    if f.len() < 2 { return None; }
    let (port_s, proto) = f[1].split_once('/')?;
    let port: u16 = port_s.parse().ok()?;
    Some(ServVal { name: f[0].into(), port, proto: proto.into(), aliases: f[2..].iter().map(|s| (*s).into()).collect() })
}

/// # C: parse one /etc/networks line:  name  net  [aliases...] (classful net)
pub(crate) fn parse_net_line(line: &str) -> Option<NetVal> {
    let f = fields(line);
    if f.len() < 2 { return None; }
    let net = parse_classful(f[1])?;
    Some(NetVal { name: f[0].into(), net, aliases: f[2..].iter().map(|s| (*s).into()).collect() })
}

/// # C: parse classful net number (10.0 → 0x0a00), host byte order
pub(crate) fn parse_classful(s: &str) -> Option<u32> {
    let mut v: u32 = 0;
    let mut n = 0u32;
    for part in s.split('.') {
        if part.is_empty() || n >= 4 { return None; }
        let o: u32 = part.parse().ok()?;
        if o > 255 { return None; }
        v = (v << 8) | o; n += 1;
    }
    if n == 0 { return None; }
    Some(v)
}

/// # C: parse one /etc/hosts line:  addr  name  [aliases...]
pub(crate) fn parse_host_line(line: &str) -> Option<HostVal> {
    use super::inet;
    let f = fields(line);
    if f.len() < 2 { return None; }
    let mut a = [0u8; 16];
    let mut a4 = [0u8; 4];
    let (addrtype, addrlen) =
        if inet::pton4(f[0].as_bytes(), &mut a4) {
            a[..4].copy_from_slice(&a4);
            (super::inet::AF_INET, 4)
        } else if inet::pton6(f[0].as_bytes(), &mut a) {
            (super::inet::AF_INET6, 16)
        } else { return None; };
    Some(HostVal { name: f[1].into(), aliases: f[2..].iter().map(|s| (*s).into()).collect(), addr: a, addrtype, addrlen })
}

// ---- packing helpers (pure; bounds-checked) ----

/// # C: append `s`+NUL into buf at pos; return (ptr, new pos) or None
pub(crate) fn put(buf: &mut [u8], pos: usize, s: &[u8]) -> Option<(*mut u8, usize)> {
    let end = pos + s.len() + 1;
    if end > buf.len() { return None; }
    buf[pos..pos + s.len()].copy_from_slice(s);
    buf[pos + s.len()] = 0;
    let p = buf[pos..].as_mut_ptr();
    Some((p, end))
}

/// Pack `strs` as NUL-terminated C strings into `buf`, writing a
/// NULL-terminated pointer vector into `ptrs`. Returns false if either is too
/// small. `ptrs` must hold strs.len()+1 slots.
/// # C: serialize a char*[] alias/address vector into caller storage
pub(crate) fn pack_vec(strs: &[&[u8]], buf: &mut [u8], ptrs: &mut [*mut u8]) -> bool {
    if strs.len() + 1 > ptrs.len() { return false; }
    let mut pos = 0;
    for (k, s) in strs.iter().enumerate() {
        match put(buf, pos, s) { Some((p, np)) => { ptrs[k] = p; pos = np; } None => return false }
    }
    ptrs[strs.len()] = core::ptr::null_mut();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_match_host() {
        assert_eq!(core::mem::size_of::<hostent>(), core::mem::size_of::<libc::hostent>());
        assert_eq!(core::mem::size_of::<servent>(), core::mem::size_of::<libc::servent>());
        assert_eq!(core::mem::size_of::<protoent>(), core::mem::size_of::<libc::protoent>());
    }

    #[test]
    fn proto_parse() {
        let p = parse_proto_line("tcp 6 TCP # transmission control").unwrap();
        assert_eq!(p.name, "tcp"); assert_eq!(p.proto, 6); assert_eq!(p.aliases, ["TCP"]);
        assert!(parse_proto_line("# comment").is_none());
    }

    #[test]
    fn serv_parse() {
        let s = parse_serv_line("http 80/tcp www www-http # web").unwrap();
        assert_eq!(s.name, "http"); assert_eq!(s.port, 80); assert_eq!(s.proto, "tcp");
        assert_eq!(s.aliases, ["www", "www-http"]);
    }

    #[test]
    fn net_parse() {
        let n = parse_net_line("loopback 127").unwrap();
        assert_eq!(n.name, "loopback"); assert_eq!(n.net, 127);
        let n2 = parse_net_line("link-local 169.254").unwrap();
        assert_eq!(n2.net, 0xa9fe);
    }

    #[test]
    fn host_parse() {
        let h = parse_host_line("127.0.0.1 localhost localhost.localdomain").unwrap();
        assert_eq!(h.name, "localhost"); assert_eq!(h.addrtype, super::super::inet::AF_INET);
        assert_eq!(h.addrlen, 4); assert_eq!(&h.addr[..4], &[127, 0, 0, 1]);
        assert_eq!(h.aliases, ["localhost.localdomain"]);
        let h6 = parse_host_line("::1 ip6-localhost ip6-loopback").unwrap();
        assert_eq!(h6.addrtype, super::super::inet::AF_INET6); assert_eq!(h6.addrlen, 16);
    }

    #[test]
    fn pack_vec_round_trip() {
        let strs: [&[u8]; 2] = [b"www", b"www-http"];
        let mut buf = [0u8; 64];
        let mut ptrs = [core::ptr::null_mut(); 4];
        assert!(pack_vec(&strs, &mut buf, &mut ptrs));
        assert!(ptrs[2].is_null());
        // SAFETY: pack_vec wrote NUL-terminated strings into buf; read them.
        unsafe {
            assert_eq!(core::ffi::CStr::from_ptr(ptrs[0] as *const i8).to_bytes(), b"www");
            assert_eq!(core::ffi::CStr::from_ptr(ptrs[1] as *const i8).to_bytes(), b"www-http");
        }
    }
}
