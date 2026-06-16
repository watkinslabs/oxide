// epoll (docs/59§6 — G19 userspace needs it; systemd's core event loop).
// create1/create/ctl/wait/pwait. `struct epoll_event` layout is the C caller's
// (packed on x86_64, not on aarch64) — we pass it through as an opaque pointer,
// matching the kernel ABI; the conformance test pins the layout vs host glibc.
// epoll_wait composes from epoll_pwait (NULL sigmask) like select←pselect6.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;
use crate::arch::syscall::{sys1, sys4, sys6};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: int epoll_create1(int flags)
#[no_mangle]
pub unsafe extern "C" fn epoll_create1(flags: i32) -> i32 {
    // SAFETY: epoll_create1(2) — flags is EPOLL_CLOEXEC or 0; no user buffers.
    ret_isize(unsafe { sys1(nr::EPOLL_CREATE1, flags as usize) }) as i32
}

// # C: int epoll_create(int size) — legacy; `size` ignored since 2.6.8.
#[no_mangle]
pub unsafe extern "C" fn epoll_create(size: i32) -> i32 {
    let _ = size;
    // SAFETY: compose from epoll_create1(0) (the modern slot); no user buffers.
    ret_isize(unsafe { sys1(nr::EPOLL_CREATE1, 0) }) as i32
}

// # C: int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
#[no_mangle]
pub unsafe extern "C" fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut c_void) -> i32 {
    // SAFETY: epoll_ctl(2) — `event` is null (for EPOLL_CTL_DEL) or a valid
    // epoll_event the kernel reads; we pass the pointer through unchanged.
    ret_isize(unsafe { sys4(nr::EPOLL_CTL, epfd as usize, op as usize, fd as usize, event as usize) }) as i32
}

// # C: int epoll_pwait(int epfd, struct epoll_event *evs, int maxevents,
//                      int timeout, const sigset_t *sigmask)
#[no_mangle]
pub unsafe extern "C" fn epoll_pwait(epfd: i32, evs: *mut c_void, maxevents: i32, timeout: i32, sigmask: *const c_void) -> i32 {
    // SAFETY: epoll_pwait(2) — `evs` is a writable array of `maxevents`
    // epoll_event; sigmask is a {ptr}+size pair (size = _NSIG/8 = 8), or null/0.
    unsafe {
        let (mp, sz) = if sigmask.is_null() { (0usize, 0usize) } else { (sigmask as usize, 8usize) };
        ret_isize(sys6(nr::EPOLL_PWAIT, epfd as usize, evs as usize, maxevents as usize, timeout as usize, mp, sz)) as i32
    }
}

// # C: int epoll_wait(int epfd, struct epoll_event *evs, int maxevents, int timeout)
#[no_mangle]
pub unsafe extern "C" fn epoll_wait(epfd: i32, evs: *mut c_void, maxevents: i32, timeout: i32) -> i32 {
    // SAFETY: epoll_wait == epoll_pwait with a NULL sigmask (the asm-generic
    // composition; aarch64 has no plain epoll_wait slot). Same buffer contract.
    unsafe { epoll_pwait(epfd, evs, maxevents, timeout, core::ptr::null()) }
}
