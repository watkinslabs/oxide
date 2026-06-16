// pthread spinlocks (docs/59§6 G11/§9.1). 4-byte int lock word; busy-CAS with a
// spin-loop hint. No futex (spinlocks never sleep, by contract).
#![cfg(feature = "freestanding")]
use core::sync::atomic::{AtomicI32, Ordering};

const EBUSY: i32 = 16;

unsafe fn word(lock: *mut i32) -> *const AtomicI32 { lock as *const AtomicI32 }

// # C: int pthread_spin_init(pthread_spinlock_t *lock, int pshared)
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_init(lock: *mut i32, _pshared: i32) -> i32 {
    // SAFETY: lock is a writable 4-byte spinlock word; 0 = unlocked.
    unsafe { (*word(lock)).store(0, Ordering::Release); } 0
}
// # C: int pthread_spin_destroy(pthread_spinlock_t *lock)
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_destroy(_lock: *mut i32) -> i32 { 0 }

// # C: int pthread_spin_lock(pthread_spinlock_t *lock)
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_lock(lock: *mut i32) -> i32 {
    // SAFETY: lock is a live spinlock word; CAS 0→1, spinning until acquired.
    unsafe {
        let w = word(lock);
        while (*w).compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
    }
    0
}
// # C: int pthread_spin_trylock(pthread_spinlock_t *lock)
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_trylock(lock: *mut i32) -> i32 {
    // SAFETY: single CAS attempt on the live lock word.
    unsafe {
        if (*word(lock)).compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { 0 } else { EBUSY }
    }
}
// # C: int pthread_spin_unlock(pthread_spinlock_t *lock)
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_unlock(lock: *mut i32) -> i32 {
    // SAFETY: release the live lock word back to 0 (unlocked).
    unsafe { (*word(lock)).store(0, Ordering::Release); } 0
}
