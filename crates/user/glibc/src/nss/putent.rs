// Account-db writers + the shadow lock (docs/59§6 §9.1, G14): putgrent/putspent
// serialize a struct group/spwd to a stream in /etc/group | /etc/shadow format;
// lckpwdf/ulckpwdf take the advisory /etc/.pwd.lock flock guarding shadow edits.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, Ordering};
use super::{group, spwd};
use crate::stdio::file::FILE;
use crate::stdio::put::{fputc, fputs};

// Write a possibly-NULL C string (NULL = empty field). -1 on error.
unsafe fn w_str(s: *const u8, f: *mut FILE) -> i32 {
    // SAFETY: s is null or a NUL-terminated C string; fputs writes it to f.
    unsafe { if s.is_null() { 0 } else { fputs(s, f) } }
}
// Write a decimal i64 (or nothing if `v == empty_sentinel`). -1 on error.
unsafe fn w_num(v: i64, empty: bool, f: *mut FILE) -> i32 {
    // SAFETY: builds the decimal text on this frame and fputs it to f.
    unsafe {
        if empty { return 0; }
        let mut buf = [0u8; 24];
        let mut i = 23; // buf[23] stays NUL
        let neg = v < 0;
        let mut u = if neg { (v as i128).unsigned_abs() as u128 } else { v as u128 };
        if u == 0 { i -= 1; buf[i] = b'0'; }
        while u > 0 { i -= 1; buf[i] = b'0' + (u % 10) as u8; u /= 10; }
        if neg { i -= 1; buf[i] = b'-'; }
        fputs(buf.as_ptr().add(i), f)
    }
}

// # C: int putgrent(const struct group *grp, FILE *stream)
#[no_mangle]
pub unsafe extern "C" fn putgrent(grp: *const group, stream: *mut c_void) -> i32 {
    // SAFETY: grp is a valid struct group; stream a writable FILE*. Emits
    // "name:passwd:gid:m1,m2,...\n". gr_mem is a NULL-terminated char* array.
    unsafe {
        let f = stream as *mut FILE;
        let g = &*grp;
        if w_str(g.gr_name, f) < 0 { return -1; }
        fputc(b':' as i32, f);
        w_str(g.gr_passwd, f);
        fputc(b':' as i32, f);
        w_num(g.gr_gid as i64, false, f);
        fputc(b':' as i32, f);
        if !g.gr_mem.is_null() {
            let mut i = 0;
            loop {
                let m = *g.gr_mem.add(i);
                if m.is_null() { break; }
                if i > 0 { fputc(b',' as i32, f); }
                w_str(m, f);
                i += 1;
            }
        }
        if fputc(b'\n' as i32, f) < 0 { -1 } else { 0 }
    }
}

// # C: int putspent(const struct spwd *p, FILE *stream)
#[no_mangle]
pub unsafe extern "C" fn putspent(p: *const spwd, stream: *mut c_void) -> i32 {
    // SAFETY: p is a valid struct spwd; stream a writable FILE*. Emits the 9
    // colon-separated shadow fields; numeric fields == -1 (flag == ~0) print
    // empty, matching glibc's putspent.
    unsafe {
        let f = stream as *mut FILE;
        let s = &*p;
        w_str(s.sp_namp, f); fputc(b':' as i32, f);
        w_str(s.sp_pwdp, f); fputc(b':' as i32, f);
        w_num(s.sp_lstchg, s.sp_lstchg == -1, f); fputc(b':' as i32, f);
        w_num(s.sp_min, s.sp_min == -1, f); fputc(b':' as i32, f);
        w_num(s.sp_max, s.sp_max == -1, f); fputc(b':' as i32, f);
        w_num(s.sp_warn, s.sp_warn == -1, f); fputc(b':' as i32, f);
        w_num(s.sp_inact, s.sp_inact == -1, f); fputc(b':' as i32, f);
        w_num(s.sp_expire, s.sp_expire == -1, f); fputc(b':' as i32, f);
        w_num(s.sp_flag as i64, s.sp_flag == u64::MAX, f);
        if fputc(b'\n' as i32, f) < 0 { -1 } else { 0 }
    }
}

// --- shadow lock -----------------------------------------------------------
static LOCK_FD: AtomicI32 = AtomicI32::new(-1);

// # C: int lckpwdf(void) — flock /etc/.pwd.lock exclusively (shadow edits).
#[no_mangle]
pub unsafe extern "C" fn lckpwdf() -> i32 {
    const O_WRONLY: i32 = 1; const O_CREAT: i32 = 0o100; const O_CLOEXEC: i32 = 0o2000000;
    const LOCK_EX: i32 = 2;
    // SAFETY: open the well-known lock file and take an exclusive flock; the fd
    // is stashed for ulckpwdf. Already-locked (fd≥0) → -1, matching glibc.
    unsafe {
        if LOCK_FD.load(Ordering::Acquire) >= 0 { return -1; }
        let fd = crate::posix::io::open(b"/etc/.pwd.lock\0".as_ptr(), O_WRONLY | O_CREAT | O_CLOEXEC, 0o600);
        if fd < 0 { return -1; }
        if crate::posix::morecalls::flock(fd, LOCK_EX) < 0 { crate::posix::io::close(fd); return -1; }
        LOCK_FD.store(fd, Ordering::Release);
        0
    }
}
// # C: int ulckpwdf(void) — release the shadow lock.
#[no_mangle]
pub unsafe extern "C" fn ulckpwdf() -> i32 {
    const LOCK_UN: i32 = 8;
    // SAFETY: release + close the stashed lock fd; -1 if not currently held.
    unsafe {
        let fd = LOCK_FD.swap(-1, Ordering::AcqRel);
        if fd < 0 { return -1; }
        crate::posix::morecalls::flock(fd, LOCK_UN);
        crate::posix::io::close(fd);
        0
    }
}
