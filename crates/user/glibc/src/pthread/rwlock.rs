// pthread_rwlock (docs/59§6 G11c). ABI-sized 56-byte pthread_rwlock_t; a
// futex over a single state word: 0=free, >0=reader count, WRITER bit =
// write-held. Reader-preferring (simple, correct; writer starvation is a
// G2-style fairness follow-up). Only the byte layout is ABI.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use crate::internal::nr;
use crate::time::clock::{clock_gettime, timespec, CLOCK_MONOTONIC, CLOCK_REALTIME};
use core::sync::atomic::{AtomicI32, Ordering};

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const WRITER: i32 = i32::MIN; // bit31: a writer holds the lock
const EBUSY: i32 = 16;
const ETIMEDOUT: i32 = 110;

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
    // SAFETY: l points at a writable pthread_rwlock_t; zero its state word and padding.
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

// abstime(absolute on clk) → Some(relative) or None if already expired.
unsafe fn remaining(clk_sel: i32, abstime: *const timespec) -> Option<timespec> {
    // SAFETY: abstime is a valid deadline; read the clock and subtract.
    unsafe {
        let clk = if clk_sel == CLOCK_MONOTONIC { CLOCK_MONOTONIC } else { CLOCK_REALTIME };
        let mut now = timespec { tv_sec: 0, tv_nsec: 0 };
        clock_gettime(clk, &mut now);
        let mut sec = (*abstime).tv_sec - now.tv_sec;
        let mut nsec = (*abstime).tv_nsec - now.tv_nsec;
        if nsec < 0 { nsec += 1_000_000_000; sec -= 1; }
        if sec < 0 { None } else { Some(timespec { tv_sec: sec, tv_nsec: nsec }) }
    }
}
unsafe fn wait_timed(l: *mut pthread_rwlock_t, v: i32, rel: *const timespec) {
    // SAFETY: l points at the live state word; FUTEX_WAIT with a relative timeout.
    unsafe { crate::arch::syscall::sys6(nr::FUTEX, st(l) as usize, FUTEX_WAIT_PRIVATE, v as usize, rel as usize, 0, 0); }
}

unsafe fn timed_rd(l: *mut pthread_rwlock_t, clk: i32, abstime: *const timespec) -> i32 {
    // SAFETY: l is a valid rwlock; acquire a read hold or return ETIMEDOUT at the deadline.
    unsafe {
        if abstime.is_null() { return pthread_rwlock_rdlock(l); }
        let a = &*st(l);
        loop {
            let s = a.load(Ordering::Relaxed);
            if s >= 0 {
                if a.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { return 0; }
            } else {
                match remaining(clk, abstime) { None => return ETIMEDOUT, Some(rel) => wait_timed(l, s, &rel) }
            }
        }
    }
}
unsafe fn timed_wr(l: *mut pthread_rwlock_t, clk: i32, abstime: *const timespec) -> i32 {
    // SAFETY: l is a valid rwlock; acquire exclusive or return ETIMEDOUT at the deadline.
    unsafe {
        if abstime.is_null() { return pthread_rwlock_wrlock(l); }
        let a = &*st(l);
        loop {
            if a.compare_exchange_weak(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() { return 0; }
            let s = a.load(Ordering::Relaxed);
            if s != 0 {
                match remaining(clk, abstime) { None => return ETIMEDOUT, Some(rel) => wait_timed(l, s, &rel) }
            }
        }
    }
}

// # C: int pthread_rwlock_timedrdlock(pthread_rwlock_t*, const struct timespec*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(l: *mut pthread_rwlock_t, abstime: *const timespec) -> i32 {
    // SAFETY: abstime is an absolute CLOCK_REALTIME deadline.
    unsafe { timed_rd(l, CLOCK_REALTIME, abstime) }
}
// # C: int pthread_rwlock_timedwrlock(pthread_rwlock_t*, const struct timespec*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(l: *mut pthread_rwlock_t, abstime: *const timespec) -> i32 {
    // SAFETY: abstime is an absolute CLOCK_REALTIME deadline.
    unsafe { timed_wr(l, CLOCK_REALTIME, abstime) }
}
// # C: int pthread_rwlock_clockrdlock(pthread_rwlock_t*, clockid_t, const struct timespec*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_clockrdlock(l: *mut pthread_rwlock_t, clk: i32, abstime: *const timespec) -> i32 {
    // SAFETY: abstime is an absolute deadline on `clk`.
    unsafe { timed_rd(l, clk, abstime) }
}
// # C: int pthread_rwlock_clockwrlock(pthread_rwlock_t*, clockid_t, const struct timespec*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_clockwrlock(l: *mut pthread_rwlock_t, clk: i32, abstime: *const timespec) -> i32 {
    // SAFETY: abstime is an absolute deadline on `clk`.
    unsafe { timed_wr(l, clk, abstime) }
}

// --- rwlockattr (kind in __pref, pshared in __pad) -------------------------
// # C: int pthread_rwlockattr_init(pthread_rwlockattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_init(a: *mut pthread_rwlockattr_t) -> i32 {
    // SAFETY: a is a writable rwlockattr; default prefer-reader, process-private.
    unsafe { (*a).__pref = 0; (*a).__pad = 0; } 0
}
// # C: int pthread_rwlockattr_destroy(pthread_rwlockattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(_a: *mut pthread_rwlockattr_t) -> i32 { 0 }
// # C: int pthread_rwlockattr_setkind_np(pthread_rwlockattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_setkind_np(a: *mut pthread_rwlockattr_t, pref: i32) -> i32 {
    if !(0..=2).contains(&pref) { return 22; } // PREFER_READER/WRITER/WRITER_NONRECURSIVE
    // SAFETY: a is a writable rwlockattr; store the preference.
    unsafe { (*a).__pref = pref; } 0
}
// # C: int pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_getkind_np(a: *const pthread_rwlockattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out valid; return the preference.
    unsafe { *out = (*a).__pref; } 0
}
// # C: int pthread_rwlockattr_setpshared(pthread_rwlockattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(a: *mut pthread_rwlockattr_t, ps: i32) -> i32 {
    if ps != 0 && ps != 1 { return 22; }
    // SAFETY: a is a writable rwlockattr; store pshared in the pad word.
    unsafe { (*a).__pad = ps; } 0
}
// # C: int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(a: *const pthread_rwlockattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out valid; read pshared from the pad word.
    unsafe { *out = (*a).__pad; } 0
}
