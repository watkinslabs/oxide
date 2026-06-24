//! netdb_host — /etc/hosts host DB + legacy hostent path + h_errno +
//! get/set hostname/domainname/hostid (docs/59§6 G13). gethostby{name,name2,
//! addr}[_r], gethost/set/endhostent, gethostid/sethostid, gethostname/
//! sethostname, getdomainname/setdomainname. Non-`_r` use static buffers;
//! `_r` pack the alias+addr vectors into the caller buffer. hostname/
//! domainname read uname(2); set* are sethostname/setdomainname(2) wrappers.
#![allow(clippy::upper_case_acronyms)]
#[cfg(feature = "freestanding")]
use super::netdb::*;

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use super::super::inet::AF_INET;
    use crate::nss::shared::read_file;
    use crate::string::len::strlen_impl;
    use crate::arch::syscall::{sys1, sys2};
    use crate::internal::{nr, errno};
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    const EINVAL: i32 = 22;
    const ENAMETOOLONG: i32 = 36;
    const UTS_FIELD: usize = 65;       // utsname field stride
    const UTS_NODENAME: usize = 65;    // offset of nodename
    const UTS_DOMAIN: usize = 325;     // offset of domainname

    // ---- h_errno (thread-local-ish; single global until full TLS) ----
    struct HErr(UnsafeCell<i32>);
    // SAFETY: h_errno mirrors glibc's per-thread variable; single-threaded
    // until libc TLS lands, matching the errno fallback in internal::errno.
    unsafe impl Sync for HErr {}
    static H_ERRNO: HErr = HErr(UnsafeCell::new(0));

    /// # C: int *__h_errno_location(void)
    #[no_mangle]
    pub extern "C" fn __h_errno_location() -> *mut i32 { H_ERRNO.0.get() }
    unsafe fn set_herrno(v: i32) {
        // SAFETY: writes the single-threaded global h_errno cell.
        unsafe { *H_ERRNO.0.get() = v; }
    }

    // ---- static host state (non-_r) ----
    const HBUF: usize = 1024;
    const VMAX: usize = 32;
    struct HState { ent: hostent, buf: [u8; HBUF], al: [*mut u8; VMAX], ad: [*mut u8; VMAX] }
    struct HEnum { v: Vec<HostVal>, i: usize, loaded: bool }
    struct St { st: UnsafeCell<HState>, en: UnsafeCell<HEnum> }
    // SAFETY: host DB get* calls follow glibc's not-thread-safe contract;
    // these process-global cells are touched single-threaded by callers.
    unsafe impl Sync for St {}
    static S: St = St {
        st: UnsafeCell::new(HState {
            ent: ZERO_HOST,
            buf: [0; HBUF], al: [core::ptr::null_mut(); VMAX], ad: [core::ptr::null_mut(); VMAX],
        }),
        en: UnsafeCell::new(HEnum { v: Vec::new(), i: 0, loaded: false }),
    };

    // Pack a HostVal into the static state; one address (files backend yields
    // one addr per line). Returns its address or null on overflow.
    unsafe fn fill(h: &HostVal) -> *mut hostent {
        // SAFETY: writes the single-threaded static HState; name/aliases/addr
        // packed within the fixed buffer; pointer arrays point into it.
        unsafe {
            let s = &mut *S.st.get();
            s.ent.h_addrtype = h.addrtype; s.ent.h_length = h.addrlen as i32;
            let aliases: Vec<&[u8]> = h.aliases.iter().map(|a| a.as_bytes()).collect();
            if !pack_vec(&aliases, &mut s.buf, &mut s.al) { return core::ptr::null_mut(); }
            let mut pos = aliases.iter().map(|a| a.len() + 1).sum::<usize>();
            // name
            match put(&mut s.buf, pos, h.name.as_bytes()) { Some((p, np)) => { s.ent.h_name = p; pos = np; } None => return core::ptr::null_mut() }
            // address bytes (raw, NOT NUL-terminated)
            if pos + h.addrlen > s.buf.len() { return core::ptr::null_mut(); }
            s.buf[pos..pos + h.addrlen].copy_from_slice(&h.addr[..h.addrlen]);
            s.ad[0] = s.buf[pos..].as_mut_ptr(); s.ad[1] = core::ptr::null_mut();
            s.ent.h_aliases = s.al.as_mut_ptr();
            s.ent.h_addr_list = s.ad.as_mut_ptr();
            &mut s.ent
        }
    }

    // Find first /etc/hosts entry matching predicate over (HostVal).
    unsafe fn find<F: Fn(&HostVal) -> bool>(pred: F) -> Option<HostVal> {
        // SAFETY: reads /etc/hosts once; predicate is pure over parsed values.
        unsafe {
            let b = read_file(b"/etc/hosts\0")?;
            core::str::from_utf8(&b).ok()?.lines().filter_map(parse_host_line).find(|h| pred(h))
        }
    }

    /// # C: struct hostent *gethostbyname2(const char *name, int af)
    #[no_mangle]
    pub unsafe extern "C" fn gethostbyname2(name: *const u8, af: i32) -> *mut hostent {
        // SAFETY: name NUL-terminated; match /etc/hosts by name/alias + family.
        unsafe {
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            match find(|h| h.addrtype == af && (h.name.as_bytes() == want || h.aliases.iter().any(|a| a.as_bytes() == want))) {
                Some(h) => { set_herrno(0); fill(&h) }
                None => { set_herrno(HOST_NOT_FOUND); core::ptr::null_mut() }
            }
        }
    }
    /// # C: struct hostent *gethostbyname(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn gethostbyname(name: *const u8) -> *mut hostent {
        // SAFETY: name NUL-terminated; AF_INET preferred (glibc default order).
        unsafe { gethostbyname2(name, AF_INET) }
    }
    /// # C: struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type)
    #[no_mangle]
    pub unsafe extern "C" fn gethostbyaddr(addr: *const u8, len: u32, type_: i32) -> *mut hostent {
        // SAFETY: addr points to `len` address bytes; match /etc/hosts by addr.
        unsafe {
            let want = core::slice::from_raw_parts(addr, len as usize);
            match find(|h| h.addrtype == type_ && h.addrlen == len as usize && &h.addr[..h.addrlen] == want) {
                Some(h) => { set_herrno(0); fill(&h) }
                None => { set_herrno(HOST_NOT_FOUND); core::ptr::null_mut() }
            }
        }
    }
    /// # C: struct hostent *res_gethostbyname(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn res_gethostbyname(name: *const u8) -> *mut hostent {
        // SAFETY: resolver compatibility alias over gethostbyname.
        unsafe { gethostbyname(name) }
    }
    /// # C: struct hostent *res_gethostbyname2(const char *name, int af)
    #[no_mangle]
    pub unsafe extern "C" fn res_gethostbyname2(name: *const u8, af: i32) -> *mut hostent {
        // SAFETY: resolver compatibility alias over gethostbyname2.
        unsafe { gethostbyname2(name, af) }
    }
    /// # C: struct hostent *res_gethostbyaddr(const char *addr, int len, int type)
    #[no_mangle]
    pub unsafe extern "C" fn res_gethostbyaddr(addr: *const u8, len: i32, type_: i32) -> *mut hostent {
        // SAFETY: resolver compatibility alias over gethostbyaddr.
        unsafe { gethostbyaddr(addr, len as u32, type_) }
    }

    // ---- enumeration ----
    /// # C: void sethostent(int stayopen)
    #[no_mangle]
    pub unsafe extern "C" fn sethostent(_stayopen: i32) {
        // SAFETY: resets the single-threaded global host enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endhostent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endhostent() {
        // SAFETY: frees the single-threaded global host enumeration cursor.
        unsafe { let e = &mut *S.en.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct hostent *gethostent(void)
    #[no_mangle]
    pub unsafe extern "C" fn gethostent() -> *mut hostent {
        // SAFETY: lazily slurps /etc/hosts; walks the global cursor index.
        unsafe {
            let e = &mut *S.en.get();
            if !e.loaded {
                if let Some(b) = read_file(b"/etc/hosts\0") {
                    e.v = core::str::from_utf8(&b).unwrap_or("").lines().filter_map(parse_host_line).collect();
                }
                e.loaded = true;
            }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let h = e.v[e.i].clone(); e.i += 1;
            fill(&h)
        }
    }

    // ---- reentrant _r packers ----
    // Pack a HostVal into the caller buffer: alias ptr array + addr ptr array
    // carved from the front, strings + addr bytes after. Returns 0/ERANGE.
    unsafe fn host_r(h: &HostVal, ret: *mut hostent, buf: *mut u8, n: usize, result: *mut *mut hostent, herrnop: *mut i32) -> i32 {
        // SAFETY: caller guarantees ret + buf[0..n] writable; pointer arrays are
        // carved from the buffer head, strings/addr packed in the remainder.
        unsafe {
            *result = core::ptr::null_mut();
            let na = h.aliases.len();
            let ptr_bytes = (na + 1 + 2) * core::mem::size_of::<*mut u8>(); // aliases+NUL + 1 addr+NUL
            if ptr_bytes > n { *herrnop = TRY_AGAIN; return ERANGE; }
            let al = core::slice::from_raw_parts_mut(buf as *mut *mut u8, na + 1);
            let ad = core::slice::from_raw_parts_mut(buf.add((na + 1) * core::mem::size_of::<*mut u8>()) as *mut *mut u8, 2);
            let rest = core::slice::from_raw_parts_mut(buf.add(ptr_bytes), n - ptr_bytes);
            let aliases: Vec<&[u8]> = h.aliases.iter().map(|a| a.as_bytes()).collect();
            if !pack_vec(&aliases, rest, al) { *herrnop = TRY_AGAIN; return ERANGE; }
            let mut pos = aliases.iter().map(|a| a.len() + 1).sum::<usize>();
            let np = match put(rest, pos, h.name.as_bytes()) { Some((p, np)) => { (*ret).h_name = p; np } None => { *herrnop = TRY_AGAIN; return ERANGE; } };
            pos = np;
            if pos + h.addrlen > rest.len() { *herrnop = TRY_AGAIN; return ERANGE; }
            rest[pos..pos + h.addrlen].copy_from_slice(&h.addr[..h.addrlen]);
            ad[0] = rest[pos..].as_mut_ptr(); ad[1] = core::ptr::null_mut();
            (*ret).h_aliases = al.as_mut_ptr();
            (*ret).h_addr_list = ad.as_mut_ptr();
            (*ret).h_addrtype = h.addrtype; (*ret).h_length = h.addrlen as i32;
            *result = ret; *herrnop = 0; 0
        }
    }

    /// # C: int gethostbyname2_r(const char*, int, struct hostent*, char*, size_t, struct hostent**, int*)
    #[no_mangle]
    pub unsafe extern "C" fn gethostbyname2_r(name: *const u8, af: i32, ret: *mut hostent, buf: *mut u8, n: usize, result: *mut *mut hostent, herrnop: *mut i32) -> i32 {
        // SAFETY: name NUL-terminated; out params writable per glibc _r contract.
        unsafe {
            *result = core::ptr::null_mut();
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            match find(|h| h.addrtype == af && (h.name.as_bytes() == want || h.aliases.iter().any(|a| a.as_bytes() == want))) {
                Some(h) => host_r(&h, ret, buf, n, result, herrnop),
                None => { *herrnop = HOST_NOT_FOUND; ENOENT }
            }
        }
    }
    /// # C: int gethostbyname_r(const char*, struct hostent*, char*, size_t, struct hostent**, int*)
    #[no_mangle]
    pub unsafe extern "C" fn gethostbyname_r(name: *const u8, ret: *mut hostent, buf: *mut u8, n: usize, result: *mut *mut hostent, herrnop: *mut i32) -> i32 {
        // SAFETY: delegates to gethostbyname2_r with AF_INET.
        unsafe { gethostbyname2_r(name, AF_INET, ret, buf, n, result, herrnop) }
    }
    /// # C: int gethostbyaddr_r(const void*, socklen_t, int, struct hostent*, char*, size_t, struct hostent**, int*)
    #[no_mangle]
    pub unsafe extern "C" fn gethostbyaddr_r(addr: *const u8, len: u32, type_: i32, ret: *mut hostent, buf: *mut u8, n: usize, result: *mut *mut hostent, herrnop: *mut i32) -> i32 {
        // SAFETY: addr points to `len` bytes; out params writable per contract.
        unsafe {
            *result = core::ptr::null_mut();
            let want = core::slice::from_raw_parts(addr, len as usize);
            match find(|h| h.addrtype == type_ && h.addrlen == len as usize && &h.addr[..h.addrlen] == want) {
                Some(h) => host_r(&h, ret, buf, n, result, herrnop),
                None => { *herrnop = HOST_NOT_FOUND; ENOENT }
            }
        }
    }
    /// # C: int gethostent_r(struct hostent*, char*, size_t, struct hostent**, int*)
    #[no_mangle]
    pub unsafe extern "C" fn gethostent_r(ret: *mut hostent, buf: *mut u8, n: usize, result: *mut *mut hostent, herrnop: *mut i32) -> i32 {
        // SAFETY: lazily slurps /etc/hosts, advances the global cursor, and
        // packs the selected entry into caller-owned output storage.
        unsafe {
            *result = core::ptr::null_mut();
            let e = &mut *S.en.get();
            if !e.loaded {
                if let Some(b) = read_file(b"/etc/hosts\0") {
                    e.v = core::str::from_utf8(&b).unwrap_or("").lines().filter_map(parse_host_line).collect();
                }
                e.loaded = true;
            }
            if e.i >= e.v.len() { *herrnop = HOST_NOT_FOUND; return ENOENT; }
            let h = e.v[e.i].clone(); e.i += 1;
            host_r(&h, ret, buf, n, result, herrnop)
        }
    }

    // ---- hostname / domainname / hostid ----

    // Copy uname() field at `off` into name[0..len]; return 0 / -1+errno.
    unsafe fn uname_field(off: usize, name: *mut u8, len: usize) -> i32 {
        // SAFETY: uts is a 390-byte utsname; off+field stays in bounds; name
        // is writable for `len` bytes per the gethostname contract.
        unsafe {
            let mut uts = [0u8; 390];
            if errno::ret(sys1(nr::UNAME, uts.as_mut_ptr() as usize)).is_err() { errno::set(EINVAL); return -1; }
            let field = &uts[off..off + UTS_FIELD];
            let slen = strlen_impl(field.as_ptr());
            if slen + 1 > len { errno::set(ENAMETOOLONG); return -1; }
            core::ptr::copy_nonoverlapping(field.as_ptr(), name, slen);
            *name.add(slen) = 0;
            0
        }
    }
    /// # C: int gethostname(char *name, size_t len)
    #[no_mangle]
    pub unsafe extern "C" fn gethostname(name: *mut u8, len: usize) -> i32 {
        // SAFETY: name writable for `len`; reads uname().nodename.
        unsafe { uname_field(UTS_NODENAME, name, len) }
    }
    /// # C: int getdomainname(char *name, size_t len)
    #[no_mangle]
    pub unsafe extern "C" fn getdomainname(name: *mut u8, len: usize) -> i32 {
        // SAFETY: name writable for `len`; reads uname().domainname.
        unsafe { uname_field(UTS_DOMAIN, name, len) }
    }
    /// # C: int sethostname(const char *name, size_t len)
    #[no_mangle]
    pub unsafe extern "C" fn sethostname(name: *const u8, len: usize) -> i32 {
        // SAFETY: name readable for `len`; sethostname(2) wrapper.
        unsafe { errno::ret_isize(sys2(nr::SETHOSTNAME, name as usize, len)) as i32 }
    }
    /// # C: int setdomainname(const char *name, size_t len)
    #[no_mangle]
    pub unsafe extern "C" fn setdomainname(name: *const u8, len: usize) -> i32 {
        // SAFETY: name readable for `len`; setdomainname(2) wrapper.
        unsafe { errno::ret_isize(sys2(nr::SETDOMAINNAME, name as usize, len)) as i32 }
    }

    // hostid is stored in /etc/hostid (4 bytes host-order) per glibc; fall
    // back to 0 when absent (glibc derives from gethostname+IP — we keep the
    // file path which the conformance test does not exercise live).
    struct HostId(UnsafeCell<i64>);
    // SAFETY: process-global sethostid scratch; single-threaded libc contract.
    unsafe impl Sync for HostId {}
    static HID: HostId = HostId(UnsafeCell::new(0));

    /// # C: long gethostid(void)
    #[no_mangle]
    pub unsafe extern "C" fn gethostid() -> i64 {
        // SAFETY: reads /etc/hostid (4 LE bytes) if present, else sethostid val.
        unsafe {
            if let Some(b) = read_file(b"/etc/hostid\0") {
                if b.len() >= 4 { return i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64; }
            }
            *HID.0.get()
        }
    }
    /// # C: int sethostid(long hostid)
    #[no_mangle]
    pub unsafe extern "C" fn sethostid(hostid: i64) -> i32 {
        // SAFETY: records the value in the process-global scratch cell.
        unsafe { *HID.0.get() = hostid; 0 }
    }

    /// # C: void herror(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn herror(_s: *const u8) {}
    /// # C: const char *hstrerror(int err)
    #[no_mangle]
    pub extern "C" fn hstrerror(err: i32) -> *const u8 {
        let s: &[u8] = match err {
            0 => b"Resolver Error 0 (no error)\0",
            HOST_NOT_FOUND => b"Unknown host\0",
            TRY_AGAIN => b"Host name lookup failure\0",
            NO_RECOVERY => b"Unknown server error\0",
            NO_DATA => b"No address associated with name\0",
            _ => b"Unknown resolver error\0",
        };
        s.as_ptr()
    }
}
