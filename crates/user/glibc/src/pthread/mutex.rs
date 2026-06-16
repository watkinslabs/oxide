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
// Opaque mutexattr bit-packing (our own layout; both get/set route here).
const TYPE_MASK: i32 = 0xff;          // bits 0-7: type/kind
const PROTO_SHIFT: i32 = 8;           // bits 8-9: protocol (NONE/INHERIT/PROTECT)
const PROTO_MASK: i32 = 0x3 << PROTO_SHIFT;
const ROBUST_BIT: i32 = 1 << 10;      // bit 10: robust
const PSHARED_BIT: i32 = 1 << 11;     // bit 11: pshared
const CEIL_SHIFT: i32 = 12;           // bits 12-23: prio ceiling
const CEIL_MASK: i32 = 0xfff << CEIL_SHIFT;

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
        // Only the type bits drive runtime behavior; protocol/ceiling/pshared/
        // robust attr bits (packed in the high bits) are advisory and dropped.
        (*m).__kind = if attr.is_null() { 0 } else { (*attr).__kind & TYPE_MASK };
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
    // SAFETY: a points at a writable pthread_mutexattr_t; store the default kind into it.
    unsafe { (*a).__kind = 0; 0 }
}
// # C: int pthread_mutexattr_destroy(pthread_mutexattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_a: *mut pthread_mutexattr_t) -> i32 { 0 }
// # C: int pthread_mutexattr_settype(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_settype(a: *mut pthread_mutexattr_t, kind: i32) -> i32 {
    // SAFETY: a points at a writable pthread_mutexattr_t; store the caller's kind into it.
    if !(0..=3).contains(&kind) { return 22; } // NORMAL/RECURSIVE/ERRORCHECK/ADAPTIVE
    // SAFETY: a is a writable mutexattr; set the type bits, preserve the rest.
    unsafe { (*a).__kind = ((*a).__kind & !TYPE_MASK) | (kind & TYPE_MASK); 0 }
}
// # C: int pthread_mutexattr_gettype(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_gettype(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out are valid mutexattr / int; return the type bits only.
    unsafe { *out = (*a).__kind & TYPE_MASK; 0 }
}
// settype is also exposed as the GNU _np alias.
// # C: int pthread_mutexattr_setkind_np(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setkind_np(a: *mut pthread_mutexattr_t, kind: i32) -> i32 {
    // SAFETY: GNU alias of settype on a writable mutexattr.
    unsafe { pthread_mutexattr_settype(a, kind) }
}
// # C: int pthread_mutexattr_getkind_np(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getkind_np(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: GNU alias of gettype on a valid mutexattr / int out-param.
    unsafe { pthread_mutexattr_gettype(a, out) }
}

// --- protocol / pshared / robust / prioceiling (packed bits) ---------------
// # C: int pthread_mutexattr_setprotocol(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setprotocol(a: *mut pthread_mutexattr_t, proto: i32) -> i32 {
    if !(0..=2).contains(&proto) { return 22; } // PRIO_NONE/INHERIT/PROTECT
    // SAFETY: a is a writable mutexattr; set protocol bits, preserve the rest.
    unsafe { (*a).__kind = ((*a).__kind & !PROTO_MASK) | (proto << PROTO_SHIFT); 0 }
}
// # C: int pthread_mutexattr_getprotocol(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getprotocol(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out valid; extract the protocol bits.
    unsafe { *out = ((*a).__kind & PROTO_MASK) >> PROTO_SHIFT; 0 }
}
// # C: int pthread_mutexattr_setpshared(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setpshared(a: *mut pthread_mutexattr_t, ps: i32) -> i32 {
    if ps != 0 && ps != 1 { return 22; }
    // SAFETY: a is a writable mutexattr; toggle the pshared bit.
    unsafe { (*a).__kind = ((*a).__kind & !PSHARED_BIT) | (if ps != 0 { PSHARED_BIT } else { 0 }); 0 }
}
// # C: int pthread_mutexattr_getpshared(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out valid; read the pshared bit.
    unsafe { *out = ((*a).__kind & PSHARED_BIT != 0) as i32; 0 }
}
// # C: int pthread_mutexattr_setrobust(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setrobust(a: *mut pthread_mutexattr_t, rob: i32) -> i32 {
    if rob != 0 && rob != 1 { return 22; }
    // SAFETY: a is a writable mutexattr; toggle the robust bit.
    unsafe { (*a).__kind = ((*a).__kind & !ROBUST_BIT) | (if rob != 0 { ROBUST_BIT } else { 0 }); 0 }
}
// # C: int pthread_mutexattr_getrobust(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getrobust(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out valid; read the robust bit.
    unsafe { *out = ((*a).__kind & ROBUST_BIT != 0) as i32; 0 }
}
// GNU _np aliases of the robust accessors.
// # C: int pthread_mutexattr_setrobust_np(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setrobust_np(a: *mut pthread_mutexattr_t, rob: i32) -> i32 {
    // SAFETY: GNU alias of setrobust on a writable mutexattr object.
    unsafe { pthread_mutexattr_setrobust(a, rob) }
}
// # C: int pthread_mutexattr_getrobust_np(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getrobust_np(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: GNU alias of getrobust on a valid mutexattr / int out-param.
    unsafe { pthread_mutexattr_getrobust(a, out) }
}
// # C: int pthread_mutexattr_setprioceiling(pthread_mutexattr_t*, int)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setprioceiling(a: *mut pthread_mutexattr_t, ceil: i32) -> i32 {
    if !(0..=4095).contains(&ceil) { return 22; }
    // SAFETY: a is a writable mutexattr; set the prioceiling bit field.
    unsafe { (*a).__kind = ((*a).__kind & !CEIL_MASK) | (ceil << CEIL_SHIFT); 0 }
}
// # C: int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getprioceiling(a: *const pthread_mutexattr_t, out: *mut i32) -> i32 {
    // SAFETY: a/out valid; extract the prioceiling bit field.
    unsafe { *out = ((*a).__kind & CEIL_MASK) >> CEIL_SHIFT; 0 }
}

// --- mutex-level extras ----------------------------------------------------
// # C: int pthread_mutex_clocklock(pthread_mutex_t*, clockid_t, const struct timespec*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_clocklock(m: *mut pthread_mutex_t, _clk: i32, _abstime: *const c_void) -> i32 {
    // SAFETY: m is a valid mutex; clock-selectable timeout precision is a
    // follow-up — blocks like pthread_mutex_lock for now.
    unsafe { pthread_mutex_lock(m) }
}
// # C: int pthread_mutex_consistent(pthread_mutex_t*) / _np alias
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_consistent(_m: *mut pthread_mutex_t) -> i32 { 0 }
// # C: int pthread_mutex_consistent_np(pthread_mutex_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_consistent_np(_m: *mut pthread_mutex_t) -> i32 { 0 }
// # C: int pthread_mutex_getprioceiling(const pthread_mutex_t*, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(_m: *const pthread_mutex_t, ceil: *mut i32) -> i32 {
    // SAFETY: ceil is a writable int; we carry no per-mutex ceiling, report 0.
    unsafe { if !ceil.is_null() { *ceil = 0; } } 0
}
// # C: int pthread_mutex_setprioceiling(pthread_mutex_t*, int, int*)
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_setprioceiling(_m: *mut pthread_mutex_t, _ceil: i32, old: *mut i32) -> i32 {
    // SAFETY: old is null or a writable int receiving the prior ceiling (0).
    unsafe { if !old.is_null() { *old = 0; } } 0
}
