//! netdb_proto — /etc/protocols: getprotobyname/getprotobynumber/getprotoent/
//! setprotoent/endprotoent (docs/59§6 G13). Static-buffer (non-`_r`) per the
//! glibc contract.
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

    const PBUF: usize = 1024;
    const ALIASMAX: usize = 32;
    struct PState { ent: protoent, buf: [u8; PBUF], al: [*mut u8; ALIASMAX] }
    struct PEnum { v: Vec<ProtoVal>, i: usize, loaded: bool }
    struct St { st: UnsafeCell<PState>, en: UnsafeCell<PEnum> }
    // SAFETY: protocol DB get* calls follow glibc's not-thread-safe contract;
    // these process-global cells are touched single-threaded by callers.
    unsafe impl Sync for St {}
    static S: St = St {
        st: UnsafeCell::new(PState {
            ent: ZERO_PROTO,
            buf: [0; PBUF], al: [core::ptr::null_mut(); ALIASMAX],
        }),
        en: UnsafeCell::new(PEnum { v: Vec::new(), i: 0, loaded: false }),
    };

    // Pack a ProtoVal into the static state; return its address or null.
    unsafe fn fill(p: &ProtoVal) -> *mut protoent {
        // SAFETY: writes the single-threaded static PState; name + aliases are
        // packed after the alias pointer array within the same fixed buffer.
        unsafe {
            let s = &mut *S.st.get();
            s.ent.p_proto = p.proto;
            let aliases: Vec<&[u8]> = p.aliases.iter().map(|a| a.as_bytes()).collect();
            if !pack_vec(&aliases, &mut s.buf, &mut s.al) { return core::ptr::null_mut(); }
            // name packed into a slot past the alias strings is awkward; instead
            // store name first by re-packing: use a small tail region of buf.
            let used = aliases.iter().map(|a| a.len() + 1).sum::<usize>();
            match put(&mut s.buf, used, p.name.as_bytes()) {
                Some((np, _)) => s.ent.p_name = np,
                None => return core::ptr::null_mut(),
            }
            s.ent.p_aliases = s.al.as_mut_ptr();
            &mut s.ent
        }
    }

    /// # C: struct protoent *getprotobyname(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getprotobyname(name: *const u8) -> *mut protoent {
        // SAFETY: name NUL-terminated; scan /etc/protocols for a name/alias hit.
        unsafe {
            let b = match read_file(b"/etc/protocols\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(p) = parse_proto_line(line) {
                    if p.name.as_bytes() == want || p.aliases.iter().any(|a| a.as_bytes() == want) { return fill(&p); }
                }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: struct protoent *getprotobynumber(int proto)
    #[no_mangle]
    pub unsafe extern "C" fn getprotobynumber(proto: i32) -> *mut protoent {
        // SAFETY: scan /etc/protocols for a matching protocol number.
        unsafe {
            let b = match read_file(b"/etc/protocols\0") { Some(b) => b, None => return core::ptr::null_mut() };
            for line in core::str::from_utf8(&b).unwrap_or("").lines() {
                if let Some(p) = parse_proto_line(line) { if p.proto == proto { return fill(&p); } }
            }
            core::ptr::null_mut()
        }
    }
    /// # C: void setprotoent(int stayopen)
    #[no_mangle]
    pub unsafe extern "C" fn setprotoent(_stayopen: i32) {
        // SAFETY: resets the single-threaded global protocols enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endprotoent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endprotoent() {
        // SAFETY: frees the single-threaded global protocols enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct protoent *getprotoent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getprotoent() -> *mut protoent {
        // SAFETY: lazily slurps /etc/protocols; walks the global cursor index.
        unsafe {
            let e = &mut *S.en.get();
            if !e.loaded {
                if let Some(b) = read_file(b"/etc/protocols\0") {
                    e.v = core::str::from_utf8(&b).unwrap_or("").lines().filter_map(parse_proto_line).collect();
                }
                e.loaded = true;
            }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let p = e.v[e.i].clone(); e.i += 1;
            fill(&p)
        }
    }
}
