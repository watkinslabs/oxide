// pthread_once (docs/59§6 G11c). 4-byte control word, 3 states: 0=never
// run, 1=in progress, 2=done. The winner runs init_routine; losers futex-
// wait until it is published. Matches glibc's pthread_once_t size (int).
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use crate::internal::nr;
use core::sync::atomic::{AtomicI32, Ordering};

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const NEVER: i32 = 0;
const RUNNING: i32 = 1;
const DONE: i32 = 2;

#[repr(C)]
pub struct pthread_once_t { __c: i32 }
const _: () = assert!(core::mem::size_of::<pthread_once_t>() == 4);

type InitFn = extern "C" fn();

// # C: int pthread_once(pthread_once_t*, void (*init_routine)(void))
#[no_mangle]
pub unsafe extern "C" fn pthread_once(once: *mut pthread_once_t, init: InitFn) -> i32 {
    // SAFETY: once is a valid control word; exactly one caller runs init,
    // the rest wait for DONE on the futex.
    unsafe {
        let a = &*(core::ptr::addr_of!((*once).__c) as *const AtomicI32);
        loop {
            match a.compare_exchange(NEVER, RUNNING, Ordering::Acquire, Ordering::Acquire) {
                Ok(_) => {
                    init();
                    a.store(DONE, Ordering::Release);
                    crate::arch::syscall::sys6(nr::FUTEX, a as *const _ as usize, FUTEX_WAKE_PRIVATE, i32::MAX as usize, 0, 0, 0);
                    return 0;
                }
                Err(DONE) => return 0,
                Err(_) => {
                    crate::arch::syscall::sys6(nr::FUTEX, a as *const _ as usize, FUTEX_WAIT_PRIVATE, RUNNING as usize, 0, 0, 0);
                }
            }
        }
    }
}
