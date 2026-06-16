//! netdb_net — /etc/networks: getnetbyname/getnetbyaddr/getnetent/setnetent/
//! endnetent (docs/59§6 G13). n_net is host byte order; n_addrtype = AF_INET.
//! Static-buffer (non-`_r`).
#![allow(clippy::upper_case_acronyms)]
#[cfg(feature = "freestanding")]
use super::netdb::*;

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use super::super::inet::AF_INET;
    use crate::nss::shared::read_file;
    use crate::string::len::strlen_impl;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    const NBUF: usize = 1024;
    const ALIASMAX: usize = 32;
    struct NState { ent: netent, buf: [u8; NBUF], al: [*mut u8; ALIASMAX] }
    struct NEnum { v: Vec<NetVal>, i: usize, loaded: bool }
    struct St { st: UnsafeCell<NState>, en: UnsafeCell<NEnum> }
    // SAFETY: networks DB get* calls follow glibc's not-thread-safe contract;
    // these process-global cells are touched single-threaded by callers.
    unsafe impl Sync for St {}
    static S: St = St {
        st: UnsafeCell::new(NState {
            ent: ZERO_NET,
            buf: [0; NBUF], al: [core::ptr::null_mut(); ALIASMAX],
        }),
        en: UnsafeCell::new(NEnum { v: Vec::new(), i: 0, loaded: false }),
    };

    unsafe fn fill(v: &NetVal) -> *mut netent {
        // SAFETY: writes the single-threaded static NState; name packed after
        // the alias pointer array+strings within the fixed buffer.
        unsafe {
            let s = &mut *S.st.get();
            s.ent.n_net = v.net; s.ent.n_addrtype = AF_INET;
            let aliases: Vec<&[u8]> = v.aliases.iter().map(|a| a.as_bytes()).collect();
            if !pack_vec(&aliases, &mut s.buf, &mut s.al) { return core::ptr::null_mut(); }
            let pos = aliases.iter().map(|a| a.len() + 1).sum::<usize>();
            match put(&mut s.buf, pos, v.name.as_bytes()) { Some((p, _)) => s.ent.n_name = p, None => return core::ptr::null_mut() }
            s.ent.n_aliases = s.al.as_mut_ptr();
            &mut s.ent
        }
    }

    /// # C: struct netent *getnetbyname(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getnetbyname(name: *const u8) -> *mut netent {
        // SAFETY: name NUL-terminated; scan /etc/networks for a name/alias hit.
        unsafe {
            let b = match read_file(b"/etc/networks\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(v) = parse_net_line(line) {
                    if v.name.as_bytes() == want || v.aliases.iter().any(|a| a.as_bytes() == want) { return fill(&v); }
                }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: struct netent *getnetbyaddr(uint32_t net, int type)
    #[no_mangle]
    pub unsafe extern "C" fn getnetbyaddr(net: u32, type_: i32) -> *mut netent {
        // SAFETY: net is host byte order; scan /etc/networks for net+addrtype.
        unsafe {
            let b = match read_file(b"/etc/networks\0") { Some(b) => b, None => return core::ptr::null_mut() };
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(v) = parse_net_line(line) { if v.net == net && type_ == AF_INET { return fill(&v); } }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: void setnetent(int stayopen)
    #[no_mangle]
    pub unsafe extern "C" fn setnetent(_stayopen: i32) {
        // SAFETY: resets the single-threaded global networks enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endnetent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endnetent() {
        // SAFETY: frees the single-threaded global networks enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct netent *getnetent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getnetent() -> *mut netent {
        // SAFETY: lazily slurps /etc/networks; walks the global cursor index.
        unsafe {
            let e = &mut *S.en.get();
            if !e.loaded {
                if let Some(b) = read_file(b"/etc/networks\0") {
                    e.v = core::str::from_utf8(&b).unwrap_or("").lines().filter_map(parse_net_line).collect();
                }
                e.loaded = true;
            }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let v = e.v[e.i].clone(); e.i += 1;
            fill(&v)
        }
    }

    const ERANGE: i32 = 34;
    unsafe fn pack(s: *mut netent, rb: *mut netent, buf: *mut u8, n: usize, result: *mut *mut netent) -> i32 {
        // SAFETY: deep-copy the static netent into the caller's _r storage.
        unsafe {
            if s.is_null() { *result = core::ptr::null_mut(); return 0; }
            match pack_r((*s).n_name, (*s).n_aliases, core::ptr::null(), buf, n) {
                Some((nm, _, al)) => { (*rb).n_name = nm; (*rb).n_aliases = al; (*rb).n_addrtype = (*s).n_addrtype; (*rb).n_net = (*s).n_net; *result = rb; 0 }
                None => { *result = core::ptr::null_mut(); ERANGE }
            }
        }
    }
    // # C: int getnetbyname_r(const char*, struct netent*, char*, size_t, struct netent**)
    #[no_mangle]
    pub unsafe extern "C" fn getnetbyname_r(name: *const u8, rb: *mut netent, buf: *mut u8, n: usize, result: *mut *mut netent) -> i32 {
        // SAFETY: deep-copy the lookup result into rb/buf.
        unsafe { pack(getnetbyname(name), rb, buf, n, result) }
    }
    // # C: int getnetbyaddr_r(uint32_t, int, struct netent*, char*, size_t, struct netent**)
    #[no_mangle]
    pub unsafe extern "C" fn getnetbyaddr_r(net: u32, type_: i32, rb: *mut netent, buf: *mut u8, n: usize, result: *mut *mut netent) -> i32 {
        // SAFETY: deep-copy the lookup result into the caller rb/buf.
        unsafe { pack(getnetbyaddr(net, type_), rb, buf, n, result) }
    }
    // # C: int getnetent_r(struct netent*, char*, size_t, struct netent**)
    #[no_mangle]
    pub unsafe extern "C" fn getnetent_r(rb: *mut netent, buf: *mut u8, n: usize, result: *mut *mut netent) -> i32 {
        // SAFETY: deep-copy the lookup result into the caller rb/buf.
        unsafe { pack(getnetent(), rb, buf, n, result) }
    }
}
