// pthread_mutex (docs/59§6 G11b). Classic 3-state futex lock (Drepper):
// __lock 0=free, 1=locked-uncontended, 2=locked-maybe-waiters. NORMAL /
// RECURSIVE / ERRORCHECK via __kind + __owner/__count. A zero-initialized
// mutex is a valid NORMAL mutex (== PTHREAD_MUTEX_INITIALIZER).
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use crate::internal::nr;
use crate::posix::ids::gettid;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, Ordering};

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const EBUSY: i32 = 16;
const EDEADLK: i32 = 35;
const RECURSIVE: i32 = 1;
const ERRORCHECK: i32 = 2;

#[repr(C)]
pub struct pthread_mutex_t {
    __lock: i32,
    __count: u32,
    __owner: i32,
    __nusers: u32,
    __kind: i32,
    __spins: i16,
    __elision: i16,
    __list: [usize; 2],
}
const _: () = assert!(core::mem::size_of::<pthread_mutex_t>() == 40);

#[repr(C)]
pub struct pthread_mutexattr_t { __kind: i32 }

unsafe fn la(m: *mut pthread_mutex_t) -> *const AtomicI32 {
    // SAFETY: __lock@0 is an i32 with the same layout as AtomicI32.
    unsafe { core::ptr::addr_of!((*m).__lock) as *const AtomicI32 }
}
unsafe fn futex_wait(a: *const AtomicI32, val: i32) {
    // SAFETY: a points at the live __lock word; FUTEX_WAIT sleeps only if
    // *a == val, so a spurious value just returns immediately.
    unsafe { crate::arch::syscall::sys6(nr::FUTEX, a as usize, FUTEX_WAIT_PRIVATE, val as usize, 0, 0, 0); }
}
unsafe fn futex_wake(a: *const AtomicI32, n: usize) {
    // SAFETY: a points at the live __lock word; wakes up to n waiters.
    unsafe { crate::arch::syscall::sys6(nr::FUTEX, a as usize, FUTEX_WAKE_PRIVATE, n, 0, 0, 0); }
}

// # C: int pthread_mutex_init(pthread_mutex_t*, const pthread_mutexattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_init(m: *mut pthread_mutex_t, attr: *const pthread_mutexattr_t) -> i32 {
    // SAFETY: m is a writable mutex; attr null or a valid mutexattr.
    unsafe {
        (*m).__lock = 0; (*m).__count = 0; (*m).__owner = 0; (*m).__nusers = 0;
        (*m).__kind = if attr.is_null() { 0 } else { (*attr).__kind };
        (*m).__spins = 0; (*m).__elision = 0; (*m).__list = [0, 0];
        0
    }
}
// # C: int pthread_mutex_destroy(pthread_mutex_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_destroy(_m: *mut pthread_mutex_t) -> i32 { 0 }

// # C: int pthread_mutex_lock(pthread_mutex_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_lock(m: *mut pthread_mutex_t) -> i32 {
    // SAFETY: m is a valid mutex; futex on its __lock word.
    unsafe {
        let me = gettid();
        let kind = (*m).__kind;
        if (kind == RECURSIVE || kind == ERRORCHECK) && (*m).__owner == me {
            if kind == RECURSIVE { (*m).__count += 1; return 0; }
            return EDEADLK;
        }
        let a = &*la(m);
        match a.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {}
            Err(mut c) => {
                if c != 2 { c = a.swap(2, Ordering::Acquire); }
                while c != 0 { futex_wait(la(m), 2); c = a.swap(2, Ordering::Acquire); }
            }
        }
        (*m).__owner = me;
        if kind == RECURSIVE { (*m).__count = 1; }
        0
    }
}
// # C: int pthread_mutex_trylock(pthread_mutex_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_trylock(m: *mut pthread_mutex_t) -> i32 {
    // SAFETY: m is a valid mutex; single CAS attempt, no blocking.
    unsafe {
        let me = gettid();
        if (*m).__kind == RECURSIVE && (*m).__owner == me { (*m).__count += 1; return 0; }
        let a = &*la(m);
        if a.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            (*m).__owner = me;
            if (*m).__kind == RECURSIVE { (*m).__count = 1; }
            0
        } else { EBUSY }
    }
}
// # C: int pthread_mutex_unlock(pthread_mutex_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_unlock(m: *mut pthread_mutex_t) -> i32 {
    // SAFETY: m is a mutex held by this thread; release + wake one waiter
    // if it was contended.
    unsafe {
        if (*m).__kind == RECURSIVE && (*m).__count > 1 { (*m).__count -= 1; return 0; }
        (*m).__owner = 0;
        if (*m).__kind == RECURSIVE { (*m).__count = 0; }
        let a = &*la(m);
        if a.swap(0, Ordering::Release) == 2 { futex_wake(la(m), 1); }
        0
    }
}
// # C: int pthread_mutex_timedlock(...) — best-effort (blocks; abstime
// honoured coarsely via the futex). Falls back to lock for now.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_timedlock(m: *mut pthread_mutex_t, _abstime: *const c_void) -> i32 {
    // SAFETY: m is a valid mutex; timeout precision is a follow-up.
    unsafe { pthread_mutex_lock(m) }
}

// # C: int pthread_mutexattr_init(pthread_mutexattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_init(a: *mut pthread_mutexattr_t) -> i32 {
    // SAFETY: a is a writable mutexattr.
    unsafe { (*a).__kind = 0; 0 }
}
// # C: int pthread_mutexattr_destroy(pthread_mutexattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_a: *mut pthread_mutexattr_t) -> i32 { 0 }
// # C: int pthread_mutexattr_settype(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_settype(a: *mut pthread_mutexattr_t, kind: i32) -> i32 {
    // SAFETY: a is a writable mutexattr.
    unsafe { (*a).__kind = kind; 0 }
}
// # C: int pthread_mutexattr_gettype(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_gettype(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out are valid mutexattr / int.
    unsafe { *out = (*a).__kind; 0 }
}
