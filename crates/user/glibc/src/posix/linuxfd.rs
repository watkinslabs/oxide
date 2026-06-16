// Linux event file descriptors (docs/59§6 — G19 userspace; systemd uses all
// of these): eventfd, signalfd, timerfd, inotify. Thin syscall wrappers;
// kernel-owned structs (itimerspec, sigset_t, inotify_event) pass through as
// pointers. eventfd/signalfd compose from the modern *2/*4 slots like glibc.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys1, sys2, sys3, sys4};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: int eventfd(unsigned int initval, int flags)
#[no_mangle]
pub unsafe extern "C" fn eventfd(initval: u32, flags: i32) -> i32 {
    // SAFETY: eventfd2(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys2(nr::EVENTFD2, initval as usize, flags as usize) }) as i32
}

// # C: int signalfd(int fd, const sigset_t *mask, int flags)
#[no_mangle]
pub unsafe extern "C" fn signalfd(fd: i32, mask: *const c_void, flags: i32) -> i32 {
    // SAFETY: signalfd4(2) — `mask` is a kernel sigset_t (8 bytes, _NSIG/8);
    // pass the pointer + size through. fd = -1 creates a new signalfd.
    ret_isize(unsafe { sys4(nr::SIGNALFD4, fd as usize, mask as usize, 8, flags as usize) }) as i32
}

// # C: int timerfd_create(int clockid, int flags)
#[no_mangle]
pub unsafe extern "C" fn timerfd_create(clockid: i32, flags: i32) -> i32 {
    // SAFETY: timerfd_create(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys2(nr::TIMERFD_CREATE, clockid as usize, flags as usize) }) as i32
}

// # C: int timerfd_settime(int fd, int flags, const struct itimerspec *new,
//                          struct itimerspec *old)
#[no_mangle]
pub unsafe extern "C" fn timerfd_settime(fd: i32, flags: i32, new: *const c_void, old: *mut c_void) -> i32 {
    // SAFETY: timerfd_settime(2) — `new`/`old` are itimerspec the kernel
    // reads/writes; `old` may be null. Pointers passed through unchanged.
    ret_isize(unsafe { sys4(nr::TIMERFD_SETTIME, fd as usize, flags as usize, new as usize, old as usize) }) as i32
}

// # C: int timerfd_gettime(int fd, struct itimerspec *curr)
#[no_mangle]
pub unsafe extern "C" fn timerfd_gettime(fd: i32, curr: *mut c_void) -> i32 {
    // SAFETY: timerfd_gettime(2) — `curr` is a writable itimerspec.
    ret_isize(unsafe { sys2(nr::TIMERFD_GETTIME, fd as usize, curr as usize) }) as i32
}

// # C: int inotify_init(void)  — legacy; compose from inotify_init1(0).
#[no_mangle]
pub unsafe extern "C" fn inotify_init() -> i32 {
    // SAFETY: inotify_init1(2) with flags 0; no user buffers.
    ret_isize(unsafe { sys1(nr::INOTIFY_INIT1, 0) }) as i32
}

// # C: int inotify_init1(int flags)
#[no_mangle]
pub unsafe extern "C" fn inotify_init1(flags: i32) -> i32 {
    // SAFETY: inotify_init1(2) — scalar arg, no user buffers.
    ret_isize(unsafe { sys1(nr::INOTIFY_INIT1, flags as usize) }) as i32
}

// # C: int inotify_add_watch(int fd, const char *path, uint32_t mask)
#[no_mangle]
pub unsafe extern "C" fn inotify_add_watch(fd: i32, path: *const c_char, mask: u32) -> i32 {
    // SAFETY: inotify_add_watch(2) — `path` is a NUL-terminated user string the
    // kernel reads; passed through unchanged.
    ret_isize(unsafe { sys3(nr::INOTIFY_ADD_WATCH, fd as usize, path as usize, mask as usize) }) as i32
}

// # C: int inotify_rm_watch(int fd, int wd)
#[no_mangle]
pub unsafe extern "C" fn inotify_rm_watch(fd: i32, wd: i32) -> i32 {
    // SAFETY: inotify_rm_watch(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys2(nr::INOTIFY_RM_WATCH, fd as usize, wd as usize) }) as i32
}
