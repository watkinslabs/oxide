//! nss shadow + supplementary groups (docs/59§6 G14). struct spwd lives in
//! mod.rs; this exposes set/get/endspent, getspnam, fgetspent (FILE*),
//! sgetspent (parse a string), the `_r` reentrant variants, and the
//! group-membership helpers getgrouplist / initgroups (initgroups wraps the
//! setgroups(2) syscall). Non-`_r` use a process-global static buffer.
#![allow(clippy::upper_case_acronyms)]

#[cfg(feature = "freestanding")]
use super::*;

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use super::super::shared::{fill_sp, read_file};
    use crate::arch::syscall::sys2;
    use crate::internal::{errno, nr};
    use crate::string::len::strlen_impl;
    use crate::stdio::file::FILE;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    const ENOENT: i32 = 2;
    const ERANGE: i32 = 34;

    struct SpEnum { v: Vec<libnss::Shadow>, i: usize, loaded: bool }
    struct Cur { sp: UnsafeCell<SpEnum> }
    // SAFETY: enumeration is the glibc not-thread-safe contract; this global
    // shadow cursor is touched single-threaded by set/get/endspent.
    unsafe impl Sync for Cur {}
    static CUR: Cur = Cur { sp: UnsafeCell::new(SpEnum { v: Vec::new(), i: 0, loaded: false }) };

    /// # C: void setspent(void)
    #[no_mangle]
    pub unsafe extern "C" fn setspent() {
        // SAFETY: resets the single-threaded global shadow enumeration cursor.
        unsafe { let e = &mut *CUR.sp.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endspent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endspent() {
        // SAFETY: frees the single-threaded global shadow enumeration cursor.
        unsafe { let e = &mut *CUR.sp.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct spwd *getspent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getspent() -> *mut spwd {
        // SAFETY: lazily slurps /etc/shadow, walks the global cursor index.
        unsafe {
            let e = &mut *CUR.sp.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/shadow\0") { e.v = libnss::parse_shadow(&b); } e.loaded = true; }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let s = e.v[e.i].clone(); e.i += 1;
            fill_sp(&s)
        }
    }
    /// # C: struct spwd *getspnam(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn getspnam(name: *const u8) -> *mut spwd {
        // SAFETY: name NUL-terminated; parse /etc/shadow, match by name.
        unsafe {
            let b = match read_file(b"/etc/shadow\0") { Some(b) => b, None => return core::ptr::null_mut() };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for s in libnss::parse_shadow(&b) { if s.name.as_bytes() == want { return fill_sp(&s); } }
            core::ptr::null_mut()
        }
    }

    // Read one non-blank, non-comment line from `f` into a heap String.
    unsafe fn next_line(f: *mut FILE) -> Option<alloc::string::String> {
        // SAFETY: f is a valid FILE*; fgets fills `buf` up to its size or NL.
        unsafe {
            let mut buf = [0u8; 4096];
            loop {
                let r = crate::stdio::read::fgets(buf.as_mut_ptr(), buf.len() as i32, f);
                if r.is_null() { return None; }
                let n = strlen_impl(buf.as_ptr());
                let line = core::str::from_utf8(&buf[..n]).ok()?.trim_end_matches('\n');
                if line.is_empty() || line.starts_with('#') { continue; }
                return Some(alloc::string::String::from(line));
            }
        }
    }

    /// # C: struct spwd *fgetspent(FILE *stream)
    #[no_mangle]
    pub unsafe extern "C" fn fgetspent(f: *mut FILE) -> *mut spwd {
        // SAFETY: reads one shadow line from FILE*, parses, fills static buf.
        unsafe {
            match next_line(f).and_then(|l| libnss::parse_shadow_line(&l)) {
                Some(s) => fill_sp(&s),
                None => core::ptr::null_mut(),
            }
        }
    }
    /// # C: struct spwd *sgetspent(const char *string)
    #[no_mangle]
    pub unsafe extern "C" fn sgetspent(string: *const u8) -> *mut spwd {
        // SAFETY: string NUL-terminated; parse one shadow line from it.
        unsafe {
            let n = strlen_impl(string);
            let bytes = core::slice::from_raw_parts(string, n);
            match core::str::from_utf8(bytes).ok().and_then(libnss::parse_shadow_line) {
                Some(s) => fill_sp(&s),
                None => core::ptr::null_mut(),
            }
        }
    }

    // Pack a Shadow into the caller buffer; set *result; return 0/ERANGE.
    unsafe fn sp_r(s: &libnss::Shadow, sp: *mut spwd, buf: *mut u8, n: usize, result: *mut *mut spwd) -> i32 {
        // SAFETY: caller guarantees sp + buf[0..n] writable; pack_shadow
        // bounds-checks the buffer and reports overflow.
        unsafe {
            let b = core::slice::from_raw_parts_mut(buf, n);
            if pack_shadow(s, b, &mut *sp) { *result = sp; 0 } else { *result = core::ptr::null_mut(); ERANGE }
        }
    }

    /// # C: int getspnam_r(const char*, struct spwd*, char*, size_t, struct spwd**)
    #[no_mangle]
    pub unsafe extern "C" fn getspnam_r(name: *const u8, sp: *mut spwd, buf: *mut u8, n: usize, result: *mut *mut spwd) -> i32 {
        // SAFETY: name NUL-terminated; out params writable per glibc contract.
        unsafe {
            *result = core::ptr::null_mut();
            let b = match read_file(b"/etc/shadow\0") { Some(b) => b, None => return ENOENT };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for s in libnss::parse_shadow(&b) { if s.name.as_bytes() == want { return sp_r(&s, sp, buf, n, result); } }
            0
        }
    }
    /// # C: int getspent_r(struct spwd*, char*, size_t, struct spwd**)
    #[no_mangle]
    pub unsafe extern "C" fn getspent_r(sp: *mut spwd, buf: *mut u8, n: usize, result: *mut *mut spwd) -> i32 {
        // SAFETY: walks the global cursor; out params writable per contract.
        unsafe {
            *result = core::ptr::null_mut();
            let e = &mut *CUR.sp.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/shadow\0") { e.v = libnss::parse_shadow(&b); } e.loaded = true; }
            if e.i >= e.v.len() { return ENOENT; }
            let s = e.v[e.i].clone(); e.i += 1;
            sp_r(&s, sp, buf, n, result)
        }
    }
    /// # C: int fgetspent_r(FILE*, struct spwd*, char*, size_t, struct spwd**)
    #[no_mangle]
    pub unsafe extern "C" fn fgetspent_r(f: *mut FILE, sp: *mut spwd, buf: *mut u8, n: usize, result: *mut *mut spwd) -> i32 {
        // SAFETY: reads one shadow line from FILE*; out params writable.
        unsafe {
            *result = core::ptr::null_mut();
            match next_line(f).and_then(|l| libnss::parse_shadow_line(&l)) {
                Some(s) => sp_r(&s, sp, buf, n, result),
                None => ENOENT,
            }
        }
    }
    /// # C: int sgetspent_r(const char*, struct spwd*, char*, size_t, struct spwd**)
    #[no_mangle]
    pub unsafe extern "C" fn sgetspent_r(string: *const u8, sp: *mut spwd, buf: *mut u8, n: usize, result: *mut *mut spwd) -> i32 {
        // SAFETY: string NUL-terminated; out params writable per contract.
        unsafe {
            *result = core::ptr::null_mut();
            let ln = strlen_impl(string);
            let bytes = core::slice::from_raw_parts(string, ln);
            match core::str::from_utf8(bytes).ok().and_then(libnss::parse_shadow_line) {
                Some(s) => sp_r(&s, sp, buf, n, result),
                None => ENOENT,
            }
        }
    }

    // ---- supplementary groups: getgrouplist / initgroups ----

    // Collect gids `user` belongs to: the seed `gid` first, then every
    // /etc/group whose member list contains `user`. Deduplicated, in scan order.
    unsafe fn member_gids(user: &[u8], gid: u32) -> Vec<u32> {
        // SAFETY: reads /etc/group via read_file; pure scan otherwise.
        unsafe {
            let mut out: Vec<u32> = Vec::new();
            out.push(gid);
            if let Some(b) = read_file(b"/etc/group\0") {
                for g in libnss::parse_group(&b) {
                    if g.members.iter().any(|m| m.as_bytes() == user) && !out.contains(&g.gid) {
                        out.push(g.gid);
                    }
                }
            }
            out
        }
    }

    /// # C: int getgrouplist(const char*, gid_t, gid_t*, int*)
    #[no_mangle]
    pub unsafe extern "C" fn getgrouplist(user: *const u8, gid: u32, groups: *mut u32, ngroups: *mut i32) -> i32 {
        // SAFETY: user NUL-terminated; groups holds *ngroups slots; writes the
        // membership gids and the actual count, returning -1 if it overflows.
        unsafe {
            let uname = core::slice::from_raw_parts(user, strlen_impl(user));
            let gids = member_gids(uname, gid);
            let cap = (*ngroups).max(0) as usize;
            let total = gids.len();
            let copy = total.min(cap);
            for (k, &g) in gids.iter().take(copy).enumerate() { *groups.add(k) = g; }
            *ngroups = total as i32;
            if total > cap { -1 } else { total as i32 }
        }
    }
    /// # C: int initgroups(const char *user, gid_t group)
    #[no_mangle]
    pub unsafe extern "C" fn initgroups(user: *const u8, group: u32) -> i32 {
        // SAFETY: user NUL-terminated; builds the gid list then setgroups(2).
        unsafe {
            let uname = core::slice::from_raw_parts(user, strlen_impl(user));
            let gids = member_gids(uname, group);
            let r = sys2(nr::SETGROUPS, gids.len(), gids.as_ptr() as usize);
            errno::ret_isize(r) as i32
        }
    }
}
