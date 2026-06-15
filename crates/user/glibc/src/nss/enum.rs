//! nss enumeration + reentrant — set/get/endpwent, set/get/endgrent,
//! fgetpwent/fgetgrent (one entry from a FILE*) and the `_r` reentrant
//! variants (docs/59§6 G14). Non-`_r` use process-global static buffers
//! (glibc's not-thread-safe contract); `_r` pack into the caller buffer and
//! set `*result`, returning 0 / ERANGE / errno. Enumeration slurps the whole
//! /etc/passwd|group once on first get* and walks an index.
#![allow(clippy::upper_case_acronyms)]

#[cfg(feature = "freestanding")]
use super::*;

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use super::super::shared::{fill_pw, fill_gr, read_file};
    use crate::string::len::strlen_impl;
    use crate::stdio::file::FILE;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    const ENOENT: i32 = 2;
    const ERANGE: i32 = 34;

    // Enumeration cursor: parsed entries + next index. Refilled on set*ent.
    struct PwEnum { v: Vec<libnss::Passwd>, i: usize, loaded: bool }
    struct GrEnum { v: Vec<libnss::Group>, i: usize, loaded: bool }
    struct Cur { pw: UnsafeCell<PwEnum>, gr: UnsafeCell<GrEnum> }
    // SAFETY: enumeration is the glibc not-thread-safe contract; these
    // process-global cursors are touched single-threaded by set/get/endent.
    unsafe impl Sync for Cur {}
    static CUR: Cur = Cur {
        pw: UnsafeCell::new(PwEnum { v: Vec::new(), i: 0, loaded: false }),
        gr: UnsafeCell::new(GrEnum { v: Vec::new(), i: 0, loaded: false }),
    };

    // ---- passwd enumeration ----

    /// # C: void setpwent(void)
    #[no_mangle]
    pub unsafe extern "C" fn setpwent() {
        // SAFETY: resets the single-threaded global passwd enumeration cursor.
        unsafe { let e = &mut *CUR.pw.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endpwent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endpwent() {
        // SAFETY: frees the single-threaded global passwd enumeration cursor.
        unsafe { let e = &mut *CUR.pw.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct passwd *getpwent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getpwent() -> *mut passwd {
        // SAFETY: lazily slurps /etc/passwd, walks the global cursor index.
        unsafe {
            let e = &mut *CUR.pw.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/passwd\0") { e.v = libnss::parse_passwd(&b); } e.loaded = true; }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let p = e.v[e.i].clone(); e.i += 1;
            fill_pw(&p)
        }
    }

    // ---- group enumeration ----

    /// # C: void setgrent(void)
    #[no_mangle]
    pub unsafe extern "C" fn setgrent() {
        // SAFETY: resets the single-threaded global group enumeration cursor.
        unsafe { let e = &mut *CUR.gr.get(); e.v.clear(); e.i = 0; e.loaded = false; }
    }
    /// # C: void endgrent(void)
    #[no_mangle]
    pub unsafe extern "C" fn endgrent() {
        // SAFETY: frees the single-threaded global group enumeration cursor.
        unsafe { let e = &mut *CUR.gr.get(); e.v = Vec::new(); e.i = 0; e.loaded = false; }
    }
    /// # C: struct group *getgrent(void)
    #[no_mangle]
    pub unsafe extern "C" fn getgrent() -> *mut group {
        // SAFETY: lazily slurps /etc/group, walks the global cursor index.
        unsafe {
            let e = &mut *CUR.gr.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/group\0") { e.v = libnss::parse_group(&b); } e.loaded = true; }
            if e.i >= e.v.len() { return core::ptr::null_mut(); }
            let g = e.v[e.i].clone(); e.i += 1;
            fill_gr(&g)
        }
    }

    // ---- fgetpwent / fgetgrent (one entry from a FILE*) ----

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

    /// # C: struct passwd *fgetpwent(FILE *stream)
    #[no_mangle]
    pub unsafe extern "C" fn fgetpwent(f: *mut FILE) -> *mut passwd {
        // SAFETY: reads one passwd line from FILE*, parses, fills static buf.
        unsafe {
            match next_line(f).and_then(|l| libnss::parse_passwd_line(&l)) {
                Some(p) => fill_pw(&p),
                None => core::ptr::null_mut(),
            }
        }
    }
    /// # C: struct group *fgetgrent(FILE *stream)
    #[no_mangle]
    pub unsafe extern "C" fn fgetgrent(f: *mut FILE) -> *mut group {
        // SAFETY: reads one group line from FILE*, parses, fills static buf.
        unsafe {
            match next_line(f).and_then(|l| libnss::parse_group_line(&l)) {
                Some(g) => fill_gr(&g),
                None => core::ptr::null_mut(),
            }
        }
    }

    // ---- reentrant _r packers ----

    // Pack a Passwd into the caller buffer; set *result; return 0/ERANGE.
    unsafe fn pw_r(p: &libnss::Passwd, pwd: *mut passwd, buf: *mut u8, n: usize, result: *mut *mut passwd) -> i32 {
        // SAFETY: caller guarantees pwd + buf[0..n] writable; pack_passwd
        // bounds-checks the buffer and reports overflow.
        unsafe {
            let b = core::slice::from_raw_parts_mut(buf, n);
            if pack_passwd(p, b, &mut *pwd) { *result = pwd; 0 } else { *result = core::ptr::null_mut(); ERANGE }
        }
    }
    // Pack a Group into the caller buffer; member vector carved from its head.
    unsafe fn gr_r(g: &libnss::Group, grp: *mut group, buf: *mut u8, n: usize, result: *mut *mut group) -> i32 {
        // SAFETY: caller guarantees grp + buf[0..n] writable; the member
        // pointer array is carved from the front of the caller buffer.
        unsafe {
            let need = (g.members.len() + 1) * core::mem::size_of::<*mut u8>();
            if need > n { *result = core::ptr::null_mut(); return ERANGE; }
            let memv = core::slice::from_raw_parts_mut(buf as *mut *mut u8, g.members.len() + 1);
            let rest = core::slice::from_raw_parts_mut(buf.add(need), n - need);
            if pack_group(g, rest, memv, &mut *grp) { *result = grp; 0 } else { *result = core::ptr::null_mut(); ERANGE }
        }
    }

    /// # C: int getpwnam_r(const char*, struct passwd*, char*, size_t, struct passwd**)
    #[no_mangle]
    pub unsafe extern "C" fn getpwnam_r(name: *const u8, pwd: *mut passwd, buf: *mut u8, n: usize, result: *mut *mut passwd) -> i32 {
        // SAFETY: name NUL-terminated; out params writable per glibc contract.
        unsafe {
            *result = core::ptr::null_mut();
            let b = match read_file(b"/etc/passwd\0") { Some(b) => b, None => return ENOENT };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for p in libnss::parse_passwd(&b) { if p.name.as_bytes() == want { return pw_r(&p, pwd, buf, n, result); } }
            0
        }
    }
    /// # C: int getpwuid_r(uid_t, struct passwd*, char*, size_t, struct passwd**)
    #[no_mangle]
    pub unsafe extern "C" fn getpwuid_r(uid: u32, pwd: *mut passwd, buf: *mut u8, n: usize, result: *mut *mut passwd) -> i32 {
        // SAFETY: out params writable per the glibc _r contract.
        unsafe {
            *result = core::ptr::null_mut();
            let b = match read_file(b"/etc/passwd\0") { Some(b) => b, None => return ENOENT };
            for p in libnss::parse_passwd(&b) { if p.uid == uid { return pw_r(&p, pwd, buf, n, result); } }
            0
        }
    }
    /// # C: int getgrnam_r(const char*, struct group*, char*, size_t, struct group**)
    #[no_mangle]
    pub unsafe extern "C" fn getgrnam_r(name: *const u8, grp: *mut group, buf: *mut u8, n: usize, result: *mut *mut group) -> i32 {
        // SAFETY: name NUL-terminated; out params writable per glibc contract.
        unsafe {
            *result = core::ptr::null_mut();
            let b = match read_file(b"/etc/group\0") { Some(b) => b, None => return ENOENT };
            let want = core::slice::from_raw_parts(name, strlen_impl(name));
            for g in libnss::parse_group(&b) { if g.name.as_bytes() == want { return gr_r(&g, grp, buf, n, result); } }
            0
        }
    }
    /// # C: int getgrgid_r(gid_t, struct group*, char*, size_t, struct group**)
    #[no_mangle]
    pub unsafe extern "C" fn getgrgid_r(gid: u32, grp: *mut group, buf: *mut u8, n: usize, result: *mut *mut group) -> i32 {
        // SAFETY: out params writable per the glibc _r contract.
        unsafe {
            *result = core::ptr::null_mut();
            let b = match read_file(b"/etc/group\0") { Some(b) => b, None => return ENOENT };
            for g in libnss::parse_group(&b) { if g.gid == gid { return gr_r(&g, grp, buf, n, result); } }
            0
        }
    }
    /// # C: int getpwent_r(struct passwd*, char*, size_t, struct passwd**)
    #[no_mangle]
    pub unsafe extern "C" fn getpwent_r(pwd: *mut passwd, buf: *mut u8, n: usize, result: *mut *mut passwd) -> i32 {
        // SAFETY: walks the global cursor; out params writable per contract.
        unsafe {
            *result = core::ptr::null_mut();
            let e = &mut *CUR.pw.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/passwd\0") { e.v = libnss::parse_passwd(&b); } e.loaded = true; }
            if e.i >= e.v.len() { return ENOENT; }
            let p = e.v[e.i].clone(); e.i += 1;
            pw_r(&p, pwd, buf, n, result)
        }
    }
    /// # C: int getgrent_r(struct group*, char*, size_t, struct group**)
    #[no_mangle]
    pub unsafe extern "C" fn getgrent_r(grp: *mut group, buf: *mut u8, n: usize, result: *mut *mut group) -> i32 {
        // SAFETY: walks the global cursor; out params writable per contract.
        unsafe {
            *result = core::ptr::null_mut();
            let e = &mut *CUR.gr.get();
            if !e.loaded { if let Some(b) = read_file(b"/etc/group\0") { e.v = libnss::parse_group(&b); } e.loaded = true; }
            if e.i >= e.v.len() { return ENOENT; }
            let g = e.v[e.i].clone(); e.i += 1;
            gr_r(&g, grp, buf, n, result)
        }
    }
    /// # C: int fgetpwent_r(FILE*, struct passwd*, char*, size_t, struct passwd**)
    #[no_mangle]
    pub unsafe extern "C" fn fgetpwent_r(f: *mut FILE, pwd: *mut passwd, buf: *mut u8, n: usize, result: *mut *mut passwd) -> i32 {
        // SAFETY: reads one passwd line from FILE*; out params writable.
        unsafe {
            *result = core::ptr::null_mut();
            match next_line(f).and_then(|l| libnss::parse_passwd_line(&l)) {
                Some(p) => pw_r(&p, pwd, buf, n, result),
                None => ENOENT,
            }
        }
    }
    /// # C: int fgetgrent_r(FILE*, struct group*, char*, size_t, struct group**)
    #[no_mangle]
    pub unsafe extern "C" fn fgetgrent_r(f: *mut FILE, grp: *mut group, buf: *mut u8, n: usize, result: *mut *mut group) -> i32 {
        // SAFETY: reads one group line from FILE*; out params writable.
        unsafe {
            *result = core::ptr::null_mut();
            match next_line(f).and_then(|l| libnss::parse_group_line(&l)) {
                Some(g) => gr_r(&g, grp, buf, n, result),
                None => ENOENT,
            }
        }
    }

    // ---- putpwent ----

    // Append a C string (or "" when null) to `out`.
    unsafe fn push_field(out: &mut alloc::vec::Vec<u8>, s: *mut u8) {
        // SAFETY: s is null or a NUL-terminated C string; copy its bytes.
        unsafe { if !s.is_null() { let mut i = 0; loop { let c = *s.add(i); if c == 0 { break; } out.push(c); i += 1; } } }
    }

    /// # C: int putpwent(const struct passwd *p, FILE *stream)
    #[no_mangle]
    pub unsafe extern "C" fn putpwent(p: *const passwd, f: *mut FILE) -> i32 {
        // SAFETY: p is a valid passwd; f a writable FILE*. Format the standard
        // /etc/passwd line `name:passwd:uid:gid:gecos:dir:shell\n` and fputs it.
        unsafe {
            if p.is_null() || f.is_null() { crate::internal::errno::set(EINVAL); return -1; }
            let pw = &*p;
            let mut line: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            push_field(&mut line, pw.pw_name); line.push(b':');
            push_field(&mut line, pw.pw_passwd); line.push(b':');
            write_u32(&mut line, pw.pw_uid); line.push(b':');
            write_u32(&mut line, pw.pw_gid); line.push(b':');
            push_field(&mut line, pw.pw_gecos); line.push(b':');
            push_field(&mut line, pw.pw_dir); line.push(b':');
            push_field(&mut line, pw.pw_shell); line.push(b'\n');
            line.push(0);
            if crate::stdio::put::fputs(line.as_ptr(), f) < 0 { -1 } else { 0 }
        }
    }
    const EINVAL: i32 = 22;
    fn write_u32(out: &mut alloc::vec::Vec<u8>, mut v: u32) {
        if v == 0 { out.push(b'0'); return; }
        let mut tmp = [0u8; 10];
        let mut i = 0;
        while v > 0 { tmp[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
        while i > 0 { i -= 1; out.push(tmp[i]); }
    }
}
