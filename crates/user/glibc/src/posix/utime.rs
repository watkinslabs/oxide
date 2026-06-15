// File timestamp ops (docs/59§6 G8). The kernel primitive is utimensat(2);
// the legacy seconds/usec forms (utime/utimes/lutimes/futimes) convert their
// times[2] into a timespec[2] and compose. NULL times = "set to now". Both
// arches share the utimensat slot (asm-generic + x86_64).
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys4;
use crate::internal::errno::ret_isize;
use crate::internal::nr;
use crate::posix::io::AT_FDCWD;

const AT_SYMLINK_NOFOLLOW: usize = 0x100;

// # C: struct utimbuf { time_t actime; time_t modtime; }
#[repr(C)]
pub struct utimbuf { pub actime: i64, pub modtime: i64 }
// # C: struct timeval (sec + usec) — see also time::clock::timeval.
#[repr(C)]
pub struct timeval { pub tv_sec: i64, pub tv_usec: i64 }
// # C: struct timespec (sec + nsec) — see also time::clock::timespec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct timespec { pub tv_sec: i64, pub tv_nsec: i64 }

// # C: int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags)
#[no_mangle]
pub unsafe extern "C" fn utimensat(dirfd: i32, path: *const u8, times: *const timespec, flags: i32) -> i32 {
    // SAFETY: utimensat(2); path is NUL-terminated (or NULL for an fd-relative
    // call) and times is NULL or a 2-element timespec array the kernel reads.
    ret_isize(unsafe { sys4(nr::UTIMENSAT, dirfd as usize, path as usize, times as usize, flags as usize) }) as i32
}
// # C: int futimens(int fd, const struct timespec times[2])
#[no_mangle]
pub unsafe extern "C" fn futimens(fd: i32, times: *const timespec) -> i32 {
    // SAFETY: composes utimensat(fd, NULL, times, 0) — the fd-relative form;
    // times is NULL or a caller-owned 2-element array read by the kernel.
    ret_isize(unsafe { sys4(nr::UTIMENSAT, fd as usize, 0, times as usize, 0) }) as i32
}

// # C: int utime(const char *path, const struct utimbuf *buf)
#[no_mangle]
pub unsafe extern "C" fn utime(path: *const u8, buf: *const utimbuf) -> i32 {
    // SAFETY: buf is NULL (set-now) or a readable utimbuf; convert seconds to a
    // timespec[2] then compose utimensat over the NUL-terminated path.
    unsafe {
        if buf.is_null() { return utimensat(AT_FDCWD, path, core::ptr::null(), 0); }
        let ts = [timespec { tv_sec: (*buf).actime, tv_nsec: 0 },
                  timespec { tv_sec: (*buf).modtime, tv_nsec: 0 }];
        utimensat(AT_FDCWD, path, ts.as_ptr(), 0)
    }
}
// # C: int utimes(const char *path, const struct timeval times[2])
#[no_mangle]
pub unsafe extern "C" fn utimes(path: *const u8, times: *const timeval) -> i32 {
    // SAFETY: times is NULL (set-now) or a readable 2-element timeval; convert
    // usec→nsec and compose utimensat over the NUL-terminated path.
    unsafe { utimes_at(AT_FDCWD, path, times, 0) }
}
// # C: int lutimes(const char *path, const struct timeval times[2])
#[no_mangle]
pub unsafe extern "C" fn lutimes(path: *const u8, times: *const timeval) -> i32 {
    // SAFETY: like utimes but does not follow a symlink (AT_SYMLINK_NOFOLLOW);
    // times is NULL or a readable 2-element timeval.
    unsafe { utimes_at(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW as i32) }
}
// # C: int futimes(int fd, const struct timeval times[2])
#[no_mangle]
pub unsafe extern "C" fn futimes(fd: i32, times: *const timeval) -> i32 {
    // SAFETY: fd-relative timeval form; converts usec→nsec then composes
    // utimensat(fd, NULL, ...); times is NULL or a readable 2-element array.
    unsafe {
        if times.is_null() { return futimens(fd, core::ptr::null()); }
        let ts = tv2ts(times);
        futimens(fd, ts.as_ptr())
    }
}

// Convert a timeval[2] (usec) to a timespec[2] (nsec). SAFETY contract: caller
// guarantees `times` points at two readable timeval entries.
unsafe fn tv2ts(times: *const timeval) -> [timespec; 2] {
    // SAFETY: caller (utimes_at/futimes) guarantees `times` is a non-NULL,
    // readable 2-element timeval array; we read both entries and rescale usec.
    unsafe {
        [timespec { tv_sec: (*times).tv_sec, tv_nsec: (*times).tv_usec * 1000 },
         timespec { tv_sec: (*times.add(1)).tv_sec, tv_nsec: (*times.add(1)).tv_usec * 1000 }]
    }
}
// Shared path-relative utimes helper for utimes/lutimes.
unsafe fn utimes_at(dirfd: i32, path: *const u8, times: *const timeval, flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; times is NULL (set-now) or a readable
    // 2-element timeval array converted to timespec before the syscall.
    unsafe {
        if times.is_null() { return utimensat(dirfd, path, core::ptr::null(), flags); }
        let ts = tv2ts(times);
        utimensat(dirfd, path, ts.as_ptr(), flags)
    }
}
