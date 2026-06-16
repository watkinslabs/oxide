// Small misc libc fns (docs/59§6 §9.1): gnu_dev_* (sys/sysmacros), swab, ftok,
// timespec_get/getres (C11/C23), group_member, ualarm. Self-contained.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::time::clock::{clock_gettime, clock_getres, timespec, CLOCK_REALTIME};

extern "C" {
    fn getgroups(size: i32, list: *mut u32) -> i32;
    fn setitimer(which: i32, new: *const c_void, old: *mut c_void) -> i32;
}

// stat `path` into a 144-byte struct stat buffer (st_dev@0, st_ino@8 both arches).
unsafe fn do_stat(path: *const c_char, buf: *mut u8) -> i32 {
    use crate::internal::nr;
    // SAFETY: path NUL-terminated; buf is a 144-byte struct stat the kernel fills.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { crate::internal::errno::ret_isize(crate::arch::syscall::sys2(nr::STAT, path as usize, buf as usize)) as i32 }
        #[cfg(not(target_arch = "x86_64"))]
        { let at_fdcwd = (-100i64) as usize;
          crate::internal::errno::ret_isize(crate::arch::syscall::sys4(nr::NEWFSTATAT, at_fdcwd, path as usize, buf as usize, 0)) as i32 }
    }
}

// --- device numbers (glibc gnu_dev_* bit layout) ---
// # C: unsigned int gnu_dev_major(dev_t dev)
#[no_mangle]
pub extern "C" fn gnu_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64)) as u32
}
// # C: unsigned int gnu_dev_minor(dev_t dev)
#[no_mangle]
pub extern "C" fn gnu_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xffu64)) as u32
}
// # C: dev_t gnu_dev_makedev(unsigned int major, unsigned int minor)
#[no_mangle]
pub extern "C" fn gnu_dev_makedev(major: u32, minor: u32) -> u64 {
    let (maj, min) = (major as u64, minor as u64);
    (min & 0xff) | ((maj & 0xfff) << 8) | ((min & !0xffu64) << 12) | ((maj & !0xfffu64) << 32)
}

// # C: void swab(const void *from, void *to, ssize_t n) — swap adjacent bytes.
#[no_mangle]
pub unsafe extern "C" fn swab(from: *const c_void, to: *mut c_void, n: isize) {
    // SAFETY: from/to are n readable/writable bytes; we copy swapping each
    // adjacent pair (an odd trailing byte is left untouched, per swab(3)).
    unsafe {
        let (f, t) = (from as *const u8, to as *mut u8);
        let mut i = 0isize;
        while i + 1 < n { *t.offset(i) = *f.offset(i + 1); *t.offset(i + 1) = *f.offset(i); i += 2; }
    }
}

// # C: key_t ftok(const char *pathname, int proj_id)
#[no_mangle]
pub unsafe extern "C" fn ftok(pathname: *const c_char, proj_id: i32) -> i32 {
    // SAFETY: stat the path into a 144-byte struct stat (st_dev@0, st_ino@8 on
    // both arches); compose the System V key the way glibc does.
    unsafe {
        let mut st = [0u8; 144];
        if do_stat(pathname, st.as_mut_ptr()) != 0 { return -1; }
        let dev = *(st.as_ptr() as *const u64);
        let ino = *(st.as_ptr().add(8) as *const u64);
        (((ino & 0xffff) | ((dev & 0xff) << 16) | (((proj_id as u64) & 0xff) << 24)) as u32) as i32
    }
}

// # C: int timespec_get(struct timespec *ts, int base) — TIME_UTC=1.
#[no_mangle]
pub unsafe extern "C" fn timespec_get(ts: *mut timespec, base: i32) -> i32 {
    // SAFETY: ts is a writable timespec; only TIME_UTC(1) is defined.
    unsafe { if base != 1 { 0 } else if clock_gettime(CLOCK_REALTIME, ts) == 0 { 1 } else { 0 } }
}
// # C: int timespec_getres(struct timespec *ts, int base) — C23.
#[no_mangle]
pub unsafe extern "C" fn timespec_getres(ts: *mut timespec, base: i32) -> i32 {
    // SAFETY: ts null or writable; only TIME_UTC(1) is defined.
    unsafe { if base != 1 { 0 } else if clock_getres(CLOCK_REALTIME, ts) == 0 { 1 } else { 0 } }
}

// # C: int group_member(gid_t gid) — is gid in the supplementary group set?
#[no_mangle]
pub unsafe extern "C" fn group_member(gid: u32) -> i32 {
    // SAFETY: query the supplementary group list into a stack buffer and scan it.
    unsafe {
        let mut g = [0u32; 64];
        let n = getgroups(g.len() as i32, g.as_mut_ptr());
        if n < 0 { return 0; }
        for i in 0..n as usize { if g[i] == gid { return 1; } }
        0
    }
}

// # C: useconds_t ualarm(useconds_t usecs, useconds_t interval)
#[no_mangle]
pub unsafe extern "C" fn ualarm(usecs: u32, interval: u32) -> u32 {
    // SAFETY: arm ITIMER_REAL via setitimer with a {value,interval} itimerval
    // (two timevals of {sec,usec}); return the previous value's remaining usecs.
    const ITIMER_REAL: i32 = 0;
    unsafe {
        // struct itimerval = { struct timeval it_interval; struct timeval it_value; }
        // timeval = { time_t tv_sec; suseconds_t tv_usec; } -> [i64;2].
        let new: [i64; 4] = [
            (interval / 1_000_000) as i64, (interval % 1_000_000) as i64,
            (usecs / 1_000_000) as i64, (usecs % 1_000_000) as i64,
        ];
        let mut old: [i64; 4] = [0; 4];
        setitimer(ITIMER_REAL, new.as_ptr() as *const c_void, old.as_mut_ptr() as *mut c_void);
        (old[2] * 1_000_000 + old[3]) as u32
    }
}
