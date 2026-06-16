// pthread barriers (docs/59§6 G11/§9.1). Futex generation barrier: each waiter
// bumps `arrived`; the one that reaches `total` resets, bumps `seq`, and wakes
// the rest (returning PTHREAD_BARRIER_SERIAL_THREAD). 32-byte ABI struct.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::internal::nr;

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const SERIAL_THREAD: i32 = -1; // PTHREAD_BARRIER_SERIAL_THREAD
const EINVAL: i32 = 22;

#[repr(C)]
pub struct pthread_barrier_t { seq: AtomicU32, arrived: AtomicU32, total: u32, _pad: [u32; 5] }
const _: () = assert!(core::mem::size_of::<pthread_barrier_t>() == 32);

#[repr(C)]
pub struct pthread_barrierattr_t { pshared: i32 }
const _: () = assert!(core::mem::size_of::<pthread_barrierattr_t>() == 4);

unsafe fn futex(a: *const AtomicU32, op: usize, val: u32) {
    // SAFETY: a points at the live seq word in the barrier; FUTEX wait/wake on it.
    unsafe { crate::arch::syscall::sys6(nr::FUTEX, a as usize, op, val as usize, 0, 0, 0); }
}

// # C: int pthread_barrier_init(pthread_barrier_t*, const pthread_barrierattr_t*, unsigned count)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_init(b: *mut pthread_barrier_t, _attr: *const c_void, count: u32) -> i32 {
    if count == 0 { return EINVAL; }
    // SAFETY: b is a writable pthread_barrier_t; initialize its words.
    unsafe {
        (*b).seq = AtomicU32::new(0);
        (*b).arrived = AtomicU32::new(0);
        (*b).total = count;
    }
    0
}

// # C: int pthread_barrier_destroy(pthread_barrier_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_destroy(_b: *mut pthread_barrier_t) -> i32 { 0 }

// # C: int pthread_barrier_wait(pthread_barrier_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_wait(b: *mut pthread_barrier_t) -> i32 {
    // SAFETY: b is a live barrier; we read its generation, count in, and either
    // release the cohort (last arrival) or sleep on the seq futex until released.
    unsafe {
        let g = (*b).seq.load(Ordering::Acquire);
        let n = (*b).arrived.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= (*b).total {
            (*b).arrived.store(0, Ordering::Release);
            (*b).seq.fetch_add(1, Ordering::AcqRel);
            futex(&(*b).seq, FUTEX_WAKE, i32::MAX as u32);
            SERIAL_THREAD
        } else {
            while (*b).seq.load(Ordering::Acquire) == g { futex(&(*b).seq, FUTEX_WAIT, g); }
            0
        }
    }
}

// --- barrierattr ---
// # C: int pthread_barrierattr_init(pthread_barrierattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_init(a: *mut pthread_barrierattr_t) -> i32 {
    // SAFETY: a is a writable barrierattr; default pshared=PRIVATE(0).
    unsafe { (*a).pshared = 0; } 0
}
// # C: int pthread_barrierattr_destroy(pthread_barrierattr_t*)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_destroy(_a: *mut pthread_barrierattr_t) -> i32 { 0 }
// # C: int pthread_barrierattr_setpshared(pthread_barrierattr_t*, int pshared)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(a: *mut pthread_barrierattr_t, pshared: i32) -> i32 {
    if pshared != 0 && pshared != 1 { return EINVAL; }
    // SAFETY: a is a writable barrierattr; store the validated pshared value.
    unsafe { (*a).pshared = pshared; } 0
}
// # C: int pthread_barrierattr_getpshared(const pthread_barrierattr_t*, int *pshared)
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(a: *const pthread_barrierattr_t, pshared: *mut i32) -> i32 {
    // SAFETY: a is a valid barrierattr; pshared a writable out-param.
    unsafe { *pshared = (*a).pshared; } 0
}
