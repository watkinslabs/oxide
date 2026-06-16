// /etc/rpc database (docs/59§6 §9.1) — getrpcent/getrpcbyname/getrpcbynumber/
// setrpcent/endrpcent (+_r). Line: `name number [aliases...]`. Non-`_r` use a
// process-global result; `_r` deep-copy into the caller buffer via netdb::pack_r.
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

    const RBUF: usize = 1024;
    const ALIASMAX: usize = 32;
    struct RState { ent: rpcent, buf: [u8; RBUF], al: [*mut u8; ALIASMAX] }
    struct REnum { v: Vec<RpcVal>, i: usize, loaded: bool }
    struct St { st: UnsafeCell<RState>, en: UnsafeCell<REnum> }
    // SAFETY: rpc DB get* calls follow glibc's not-thread-safe contract; these
    // process-global cells are touched single-threaded by callers.
    unsafe impl Sync for St {}
    static S: St = St {
        st: UnsafeCell::new(RState { ent: ZERO_RPC, buf: [0; RBUF], al: [core::ptr::null_mut(); ALIASMAX] }),
        en: UnsafeCell::new(REnum { v: Vec::new(), i: 0, loaded: false }),
    };

    unsafe fn fill(p: &RpcVal) -> *mut rpcent {
        // SAFETY: pack name + aliases into the single-threaded static buffer.
        unsafe {
            let s = &mut *S.st.get();
            s.ent.r_number = p.number;
            let aliases: Vec<&[u8]> = p.aliases.iter().map(|a| a.as_bytes()).collect();
            if !pack_vec(&aliases, &mut s.buf, &mut s.al) { return core::ptr::null_mut(); }
            let used = aliases.iter().map(|a| a.len() + 1).sum::<usize>();
            match put(&mut s.buf, used, p.name.as_bytes()) { Some((np, _)) => s.ent.r_name = np, None => return core::ptr::null_mut() }
            s.ent.r_aliases = s.al.as_mut_ptr();
            &mut s.ent
        }
    }

    /// # C: struct rpcent *getrpcbyname(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getrpcbyname(name: *const u8) -> *mut rpcent {
        // SAFETY: name NUL-terminated; scan /etc/rpc for a name/alias hit.
        unsafe {
            let b = match read_file(b"/etc/rpc\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(p) = parse_rpc_line(line) {
                    if p.name.as_bytes() == want || p.aliases.iter().any(|a| a.as_bytes() == want) { return fill(&p); }
                }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: struct rpcent *getrpcbynumber(int number)
    #[no_mangle]
    pub unsafe extern "C" fn getrpcbynumber(number: i32) -> *mut rpcent {
        // SAFETY: scan /etc/rpc for a matching program number.
        unsafe {
            let b = match read_file(b"/etc/rpc\0") { Some(b) => b, None => return core::ptr::null_mut() };
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(p) = parse_rpc_line(line) { if p.number == number { return fill(&p); } }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: void setrpcent(int stayopen)
    #[no_mangle]
    pub unsafe extern "C" fn setrpcent(_stayopen: i32) {
        // SAFETY: resets the single-threaded global rpc enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endrpcent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endrpcent() {
        // SAFETY: frees the single-threaded global rpc enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct rpcent *getrpcent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getrpcent() -> *mut rpcent {
        // SAFETY: lazily slurps /etc/rpc; walks the global cursor index.
        unsafe {
            let e = &mut *S.en.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/rpc\0") { e.v = core::str::from_utf8(&b).unwrap_or("").lines().filter_map(parse_rpc_line).collect(); } e.loaded = true; }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let v = e.v[e.i].clone(); e.i += 1;
            fill(&v)
        }
    }

    const ERANGE: i32 = 34;
    unsafe fn pack(s: *mut rpcent, rb: *mut rpcent, buf: *mut u8, n: usize, result: *mut *mut rpcent) -> i32 {
        // SAFETY: deep-copy the static rpcent into the caller's _r storage.
        unsafe {
            if s.is_null() { *result = core::ptr::null_mut(); return 0; }
            match pack_r((*s).r_name, (*s).r_aliases, core::ptr::null(), buf, n) {
                Some((nm, _, al)) => { (*rb).r_name = nm; (*rb).r_aliases = al; (*rb).r_number = (*s).r_number; *result = rb; 0 }
                None => { *result = core::ptr::null_mut(); ERANGE }
            }
        }
    }
    // # C: int getrpcbyname_r(const char*, struct rpcent*, char*, size_t, struct rpcent**)
    #[no_mangle]
    pub unsafe extern "C" fn getrpcbyname_r(name: *const u8, rb: *mut rpcent, buf: *mut u8, n: usize, result: *mut *mut rpcent) -> i32 {
        // SAFETY: deep-copy the lookup result into rb/buf.
        unsafe { pack(getrpcbyname(name), rb, buf, n, result) }
    }
    // # C: int getrpcbynumber_r(int, struct rpcent*, char*, size_t, struct rpcent**)
    #[no_mangle]
    pub unsafe extern "C" fn getrpcbynumber_r(number: i32, rb: *mut rpcent, buf: *mut u8, n: usize, result: *mut *mut rpcent) -> i32 {
        // SAFETY: deep-copy the lookup result into rb/buf.
        unsafe { pack(getrpcbynumber(number), rb, buf, n, result) }
    }
    // # C: int getrpcent_r(struct rpcent*, char*, size_t, struct rpcent**)
    #[no_mangle]
    pub unsafe extern "C" fn getrpcent_r(rb: *mut rpcent, buf: *mut u8, n: usize, result: *mut *mut rpcent) -> i32 {
        // SAFETY: deep-copy the next entry into rb/buf.
        unsafe { pack(getrpcent(), rb, buf, n, result) }
    }
}
