// pthread_cond (docs/59§6 G11c). ABI-sized 48-byte pthread_cond_t; a
// sequence-futex condvar (read seq under the mutex, release, wait on seq).
// Correct (no lost wakeups) though not glibc's internal G1/G2 algorithm —
// only the byte layout is part of the ABI. Default clock REALTIME; MONOTONIC
// selectable via condattr.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use super::mutex::{pthread_mutex_lock, pthread_mutex_t, pthread_mutex_unlock};
use crate::internal::nr;
use crate::time::clock::{clock_gettime, timespec, CLOCK_MONOTONIC, CLOCK_REALTIME};
use core::sync::atomic::{AtomicU32, Ordering};

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const ETIMEDOUT: i32 = 110;

#[repr(C)]
pub struct pthread_cond_t {
    __seq: u32,
    __clock: i32,
    __pad: [u32; 10],
}
const _: () = assert!(core::mem::size_of::<pthread_cond_t>() == 48);

#[repr(C)]
pub struct pthread_condattr_t { __clock: i32 }

unsafe fn seq(c: *mut pthread_cond_t) -> *const AtomicU32 {
    // SAFETY: __seq@0 is a u32 with the same layout as AtomicU32.
    unsafe { core::ptr::addr_of!((*c).__seq) as *const AtomicU32 }
}

// # C: int pthread_cond_init(pthread_cond_t*, const pthread_condattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_init(c: *mut pthread_cond_t, attr: *const pthread_condattr_t) -> i32 {
    // SAFETY: c is a writable condvar; attr null or a valid condattr.
    unsafe {
        (*c).__seq = 0;
        (*c).__clock = if attr.is_null() { CLOCK_REALTIME } else { (*attr).__clock };
        (*c).__pad = [0; 10];
        0
    }
}
// # C: int pthread_cond_destroy(pthread_cond_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_destroy(_c: *mut pthread_cond_t) -> i32 { 0 }

// # C: int pthread_cond_signal(pthread_cond_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_signal(c: *mut pthread_cond_t) -> i32 {
    // SAFETY: c is a valid condvar; bump seq and wake one waiter.
    unsafe {
        (*seq(c)).fetch_add(1, Ordering::Release);
        crate::arch::syscall::sys6(nr::FUTEX, seq(c) as usize, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
        0
    }
}
// # C: int pthread_cond_broadcast(pthread_cond_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_broadcast(c: *mut pthread_cond_t) -> i32 {
    // SAFETY: c is a valid condvar; bump seq and wake all waiters.
    unsafe {
        (*seq(c)).fetch_add(1, Ordering::Release);
        crate::arch::syscall::sys6(nr::FUTEX, seq(c) as usize, FUTEX_WAKE_PRIVATE, i32::MAX as usize, 0, 0, 0);
        0
    }
}

unsafe fn wait_common(c: *mut pthread_cond_t, m: *mut pthread_mutex_t, to: *const timespec) -> i32 {
    // SAFETY: c/m are valid, m is held by the caller; we snapshot seq while
    // holding m, drop m, futex-wait, then reacquire m (POSIX contract).
    unsafe {
        let observed = (*seq(c)).load(Ordering::Relaxed);
        pthread_mutex_unlock(m);
        let r = crate::arch::syscall::sys6(nr::FUTEX, seq(c) as usize, FUTEX_WAIT_PRIVATE, observed as usize, to as usize, 0, 0);
        pthread_mutex_lock(m);
        if r == -(ETIMEDOUT as isize) { ETIMEDOUT } else { 0 }
    }
}

// # C: int pthread_cond_wait(pthread_cond_t*, pthread_mutex_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_wait(c: *mut pthread_cond_t, m: *mut pthread_mutex_t) -> i32 {
    // SAFETY: c/m valid; m held by caller.
    unsafe { wait_common(c, m, core::ptr::null()) }
}

// # C: int pthread_cond_timedwait(pthread_cond_t*, pthread_mutex_t*, const struct timespec*)
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_timedwait(c: *mut pthread_cond_t, m: *mut pthread_mutex_t, abstime: *const timespec) -> i32 {
    // SAFETY: c/m valid, m held; abstime a valid absolute deadline. FUTEX_WAIT
    // takes a relative timeout, so convert abstime - now on the cond's clock.
    unsafe {
        if abstime.is_null() { return wait_common(c, m, core::ptr::null()); }
        let clk = if (*c).__clock == CLOCK_MONOTONIC { CLOCK_MONOTONIC } else { CLOCK_REALTIME };
        let mut now = timespec { tv_sec: 0, tv_nsec: 0 };
        clock_gettime(clk, &mut now);
        let mut sec = (*abstime).tv_sec - now.tv_sec;
        let mut nsec = (*abstime).tv_nsec - now.tv_nsec;
        if nsec < 0 { nsec += 1_000_000_000; sec -= 1; }
        if sec < 0 { return ETIMEDOUT; }
        let rel = timespec { tv_sec: sec, tv_nsec: nsec };
        wait_common(c, m, &rel)
    }
}

// # C: int pthread_condattr_init(pthread_condattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_init(a: *mut pthread_condattr_t) -> i32 {
    // SAFETY: a is a writable condattr.
    unsafe { (*a).__clock = CLOCK_REALTIME; 0 }
}
// # C: int pthread_condattr_destroy(pthread_condattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_destroy(_a: *mut pthread_condattr_t) -> i32 { 0 }
// # C: int pthread_condattr_setclock(pthread_condattr_t*, clockid_t)
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_setclock(a: *mut pthread_condattr_t, clk: i32) -> i32 {
    // SAFETY: a is a writable condattr.
    unsafe { (*a).__clock = clk; 0 }
}
// # C: int pthread_condattr_getclock(const pthread_condattr_t*, clockid_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_getclock(a: *const pthread_condattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out are valid condattr / clockid out-param.
    unsafe { *out = (*a).__clock; 0 }
}
