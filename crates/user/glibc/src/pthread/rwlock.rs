// pthread_rwlock (docs/59§6 G11c). ABI-sized 56-byte pthread_rwlock_t; a
// futex over a single state word: 0=free, >0=reader count, WRITER bit =
// write-held. Reader-preferring (simple, correct; writer starvation is a
// G2-style fairness follow-up). Only the byte layout is ABI.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use crate::internal::nr;
use core::sync::atomic::{AtomicI32, Ordering};

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const WRITER: i32 = i32::MIN; // bit31: a writer holds the lock
const EBUSY: i32 = 16;

#[repr(C)]
pub struct pthread_rwlock_t {
    __state: i32,
    __pad: [i32; 13],
}
const _: () = assert!(core::mem::size_of::<pthread_rwlock_t>() == 56);

#[repr(C)]
pub struct pthread_rwlockattr_t { __pref: i32, __pad: i32 }

unsafe fn st(l: *mut pthread_rwlock_t) -> *const AtomicI32 {
    // SAFETY: __state@0 is an i32 with the same layout as AtomicI32.
    unsafe { core::ptr::addr_of!((*l).__state) as *const AtomicI32 }
}
unsafe fn wait(l: *mut pthread_rwlock_t, v: i32) {
    // SAFETY: l points at the live state word; FUTEX_WAIT sleeps only if it
    // still reads v.
    unsafe { crate::arch::syscall::sys6(nr::FUTEX, st(l) as usize, FUTEX_WAIT_PRIVATE, v as usize, 0, 0, 0); }
}
unsafe fn wake(l: *mut pthread_rwlock_t) {
    // SAFETY: l points at the live state word; wake all blocked threads.
    unsafe { crate::arch::syscall::sys6(nr::FUTEX, st(l) as usize, FUTEX_WAKE_PRIVATE, i32::MAX as usize, 0, 0, 0); }
}

// # C: int pthread_rwlock_init(pthread_rwlock_t*, const pthread_rwlockattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_init(l: *mut pthread_rwlock_t, _attr: *const pthread_rwlockattr_t) -> i32 {
    // SAFETY: l is a writable rwlock.
    unsafe { (*l).__state = 0; (*l).__pad = [0; 13]; 0 }
}
// # C: int pthread_rwlock_destroy(pthread_rwlock_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_destroy(_l: *mut pthread_rwlock_t) -> i32 { 0 }

// # C: int pthread_rwlock_rdlock(pthread_rwlock_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_rdlock(l: *mut pthread_rwlock_t) -> i32 {
    // SAFETY: l is a valid rwlock; spin/futex until no writer holds it.
    unsafe {
        let a = &*st(l);
        loop {
            let s = a.load(Ordering::Relaxed);
            if s >= 0 {
                if a.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { return 0; }
            } else {
                wait(l, s);
            }
        }
    }
}
// # C: int pthread_rwlock_tryrdlock(pthread_rwlock_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(l: *mut pthread_rwlock_t) -> i32 {
    // SAFETY: l is a valid rwlock; single attempt.
    unsafe {
        let a = &*st(l);
        let s = a.load(Ordering::Relaxed);
        if s >= 0 && a.compare_exchange(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { 0 } else { EBUSY }
    }
}
// # C: int pthread_rwlock_wrlock(pthread_rwlock_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_wrlock(l: *mut pthread_rwlock_t) -> i32 {
    // SAFETY: l is a valid rwlock; futex until the lock is free, then claim
    // it exclusively via the WRITER bit.
    unsafe {
        let a = &*st(l);
        loop {
            if a.compare_exchange_weak(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() { return 0; }
            let s = a.load(Ordering::Relaxed);
            if s != 0 { wait(l, s); }
        }
    }
}
// # C: int pthread_rwlock_trywrlock(pthread_rwlock_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(l: *mut pthread_rwlock_t) -> i32 {
    // SAFETY: l is a valid rwlock; single attempt.
    unsafe {
        let a = &*st(l);
        if a.compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() { 0 } else { EBUSY }
    }
}
// # C: int pthread_rwlock_unlock(pthread_rwlock_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_unlock(l: *mut pthread_rwlock_t) -> i32 {
    // SAFETY: l is held by the caller (read or write); release and wake
    // anyone blocked.
    unsafe {
        let a = &*st(l);
        let s = a.load(Ordering::Relaxed);
        if s < 0 {
            a.store(0, Ordering::Release); // writer release
            wake(l);
        } else if a.fetch_sub(1, Ordering::Release) == 1 {
            wake(l); // last reader out — wake a waiting writer
        }
        0
    }
}
