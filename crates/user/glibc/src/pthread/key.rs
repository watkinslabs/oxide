// pthread TLS keys (docs/59§6 G11c). Key slots are allocated from a global
// table (used flag + destructor); the per-thread *values* live in the
// thread's TCB key array (super::Tcb::keys), so getspecific/setspecific are
// O(1) and isolated per thread. Destructor invocation at thread exit is a
// follow-up tied to the G12 TLS teardown path.
#![cfg(feature = "freestanding")]
#![allow(clippy::declare_interior_mutable_const, clippy::borrow_interior_mutable_const)]
use super::{current_tcb, KEYS_MAX};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

const EAGAIN: i32 = 11;
const EINVAL: i32 = 22;

type Dtor = Option<extern "C" fn(*mut c_void)>;

struct Slot { used: AtomicBool, dtor: core::cell::UnsafeCell<Dtor> }
// SAFETY: `used` gates access — a slot's dtor is written only by the thread
// that wins the used CAS, before publishing, and read only while used.
unsafe impl Sync for Slot {}

const SLOT_INIT: Slot = Slot { used: AtomicBool::new(false), dtor: core::cell::UnsafeCell::new(None) };
static KEYS: [Slot; KEYS_MAX] = [SLOT_INIT; KEYS_MAX];

// # C: int pthread_key_create(pthread_key_t*, void (*destructor)(void*))
#[no_mangle]
pub unsafe extern "C" fn pthread_key_create(key: *mut u32, dtor: Dtor) -> i32 {
    // SAFETY: key is a writable pthread_key_t out-param; claim a free slot.
    unsafe {
        for (i, slot) in KEYS.iter().enumerate() {
            if slot.used.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                *slot.dtor.get() = dtor;
                *key = i as u32;
                return 0;
            }
        }
        EAGAIN
    }
}

// # C: int pthread_key_delete(pthread_key_t)
#[no_mangle]
pub unsafe extern "C" fn pthread_key_delete(key: u32) -> i32 {
    // SAFETY: key indexes the global slot table; release it.
    unsafe {
        let k = key as usize;
        if k >= KEYS_MAX || !KEYS[k].used.load(Ordering::Acquire) { return EINVAL; }
        *KEYS[k].dtor.get() = None;
        KEYS[k].used.store(false, Ordering::Release);
        0
    }
}

// # C: void *pthread_getspecific(pthread_key_t)
#[no_mangle]
pub unsafe extern "C" fn pthread_getspecific(key: u32) -> *mut c_void {
    // SAFETY: read this thread's TCB key value; out-of-range keys map to NULL.
    unsafe {
        let k = key as usize;
        let tcb = current_tcb();
        if k >= KEYS_MAX || tcb.is_null() { return core::ptr::null_mut(); }
        (*tcb).keys[k]
    }
}

// # C: int pthread_setspecific(pthread_key_t, const void*)
#[no_mangle]
pub unsafe extern "C" fn pthread_setspecific(key: u32, val: *const c_void) -> i32 {
    // SAFETY: write this thread's TCB key value.
    unsafe {
        let k = key as usize;
        let tcb = current_tcb();
        if k >= KEYS_MAX || tcb.is_null() || !KEYS[k].used.load(Ordering::Acquire) { return EINVAL; }
        (*tcb).keys[k] = val as *mut c_void;
        0
    }
}
