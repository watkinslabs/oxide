//! netdb_serv — /etc/services: getservbyname/getservbyport/getservent/
//! setservent/endservent (docs/59§6 G13). s_port is network byte order;
//! getservbyport takes a network-order port. Static-buffer (non-`_r`).
#![allow(clippy::upper_case_acronyms)]
#[cfg(feature = "freestanding")]
use super::netdb::*;

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::nss::shared::read_file;
    use crate::string::len::strlen_impl;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    const SBUF: usize = 1024;
    const ALIASMAX: usize = 32;
    struct SvState { ent: servent, buf: [u8; SBUF], al: [*mut u8; ALIASMAX] }
    struct SvEnum { v: Vec<ServVal>, i: usize, loaded: bool }
    struct St { st: UnsafeCell<SvState>, en: UnsafeCell<SvEnum> }
    // SAFETY: services DB get* calls follow glibc's not-thread-safe contract;
    // these process-global cells are touched single-threaded by callers.
    unsafe impl Sync for St {}
    static S: St = St {
        st: UnsafeCell::new(SvState {
            ent: ZERO_SERV,
            buf: [0; SBUF], al: [core::ptr::null_mut(); ALIASMAX],
        }),
        en: UnsafeCell::new(SvEnum { v: Vec::new(), i: 0, loaded: false }),
    };

    // Pack a ServVal into static state. s_port stored network byte order.
    unsafe fn fill(v: &ServVal) -> *mut servent {
        // SAFETY: writes the single-threaded static SvState; name/proto packed
        // after the alias pointer array+strings within the fixed buffer.
        unsafe {
            let s = &mut *S.st.get();
            s.ent.s_port = (v.port.to_be() as i32) & 0xffff;
            let aliases: Vec<&[u8]> = v.aliases.iter().map(|a| a.as_bytes()).collect();
            if !pack_vec(&aliases, &mut s.buf, &mut s.al) { return core::ptr::null_mut(); }
            let mut pos = aliases.iter().map(|a| a.len() + 1).sum::<usize>();
            match put(&mut s.buf, pos, v.name.as_bytes()) { Some((p, np)) => { s.ent.s_name = p; pos = np; } None => return core::ptr::null_mut() }
            match put(&mut s.buf, pos, v.proto.as_bytes()) { Some((p, _)) => s.ent.s_proto = p, None => return core::ptr::null_mut() }
            s.ent.s_aliases = s.al.as_mut_ptr();
            &mut s.ent
        }
    }

    // proto NULL → match any; else require exact proto string match.
    unsafe fn proto_ok(want: *const u8, have: &str) -> bool {
        // SAFETY: want is null or a NUL-terminated proto string ("tcp"/"udp").
        unsafe { want.is_null() || core::slice::from_raw_parts(want, strlen_impl(want)) == have.as_bytes() }
    }

    /// # C: struct servent *getservbyname(const char *name, const char *proto)
    #[no_mangle]
    pub unsafe extern "C" fn getservbyname(name: *const u8, proto: *const u8) -> *mut servent {
        // SAFETY: name NUL-terminated; proto null or NUL-terminated; scan svcs.
        unsafe {
            let b = match read_file(b"/etc/services\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(v) = parse_serv_line(line) {
                    let nmatch = v.name.as_bytes() == want || v.aliases.iter().any(|a| a.as_bytes() == want);
                    if nmatch && proto_ok(proto, &v.proto) { return fill(&v); }
                }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: struct servent *getservbyport(int port, const char *proto)
    #[no_mangle]
    pub unsafe extern "C" fn getservbyport(port: i32, proto: *const u8) -> *mut servent {
        // SAFETY: port is network byte order (htons of host port); proto null
        // or NUL-terminated. Scan /etc/services for the matching port+proto.
        unsafe {
            let host_port = u16::from_be((port & 0xffff) as u16);
            let b = match read_file(b"/etc/services\0") { Some(b) => b, None => return core::ptr::null_mut() };
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(v) = parse_serv_line(line) {
                    if v.port == host_port && proto_ok(proto, &v.proto) { return fill(&v); }
                }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: void setservent(int stayopen)
    #[no_mangle]
    pub unsafe extern "C" fn setservent(_stayopen: i32) {
        // SAFETY: resets the single-threaded global services enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endservent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endservent() {
        // SAFETY: frees the single-threaded global services enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct servent *getservent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getservent() -> *mut servent {
        // SAFETY: lazily slurps /etc/services; walks the global cursor index.
        unsafe {
            let e = &mut *S.en.get();
            if !e.loaded {
                if let Some(b) = read_file(b"/etc/services\0") {
                    e.v = core::str::from_utf8(&b).unwrap_or("").lines().filter_map(parse_serv_line).collect();
                }
                e.loaded = true;
            }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let v = e.v[e.i].clone(); e.i += 1;
            fill(&v)
        }
    }
}
