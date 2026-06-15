// lio_listio — submit a list of aio requests, optionally waiting for all
// (LIO_WAIT) or returning immediately (LIO_NOWAIT). docs/59§6 G17.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use super::ctl::aio_suspend;
use super::{aiocb, enqueue, error_of, sigevent, EINPROGRESS, EINVAL, LIO_NOP, LIO_READ, LIO_WRITE};
use crate::internal::errno::set;

// lio_listio mode (host <aio.h> enum).
const LIO_WAIT: i32 = 0;
const LIO_NOWAIT: i32 = 1;

// # C: int lio_listio(int mode, struct aiocb *const list[], int nent,
//                     struct sigevent *sig)
#[no_mangle]
pub unsafe extern "C" fn lio_listio(mode: i32, list: *const *mut aiocb, nent: i32, sig: *mut sigevent) -> i32 {
    // SAFETY: list is a caller array of nent aiocb pointers (NULL/ LIO_NOP
    // entries skipped); each is dispatched by aio_lio_opcode. On LIO_WAIT we
    // block until all complete, then (best-effort) fire the list sigevent.
    unsafe {
        if (mode != LIO_WAIT && mode != LIO_NOWAIT) || list.is_null() || nent < 0 {
            set(EINVAL);
            return -1;
        }
        let mut err = false;
        for i in 0..nent as isize {
            let cb = *list.offset(i);
            if cb.is_null() { continue; }
            match (*cb).aio_lio_opcode {
                LIO_NOP => {}
                LIO_READ => { if enqueue(cb, LIO_READ) != 0 { err = true; } }
                LIO_WRITE => { if enqueue(cb, LIO_WRITE) != 0 { err = true; } }
                _ => { set(EINVAL); return -1; }
            }
        }
        if mode == LIO_NOWAIT {
            return if err { -1 } else { 0 };
        }
        // LIO_WAIT: spin aio_suspend over the list until none remain queued.
        let cast = list as *const *const aiocb;
        loop {
            let mut pending = false;
            for i in 0..nent as isize {
                let cb = *list.offset(i);
                if !cb.is_null() && (*cb).aio_lio_opcode != LIO_NOP && error_of(cb) == EINPROGRESS {
                    pending = true;
                    break;
                }
            }
            if !pending { break; }
            aio_suspend(cast, nent, core::ptr::null());
        }
        list_notify(sig);
        if err { -1 } else { 0 }
    }
}

// Fire the list-completion notification (SIGEV_SIGNAL/THREAD/NONE) after a
// LIO_WAIT batch. Reuses the per-request notify path via a synthetic carrier.
unsafe fn list_notify(sig: *mut sigevent) {
    // SAFETY: sig is NULL (no notification) or a caller-owned sigevent; we
    // only read its discriminant and dispatch the same best-effort paths the
    // per-request worker uses (signal via tgkill, thread via pthread_create).
    unsafe {
        if sig.is_null() { return; }
        // SIGEV_NONE / SIGEV_THREAD at list level = nothing; only SIGEV_SIGNAL fires.
        if (*sig).sigev_notify == super::SIGEV_SIGNAL {
            let signo = (*sig).sigev_signo;
            if signo > 0 {
                let pid = crate::posix::io::getpid();
                let tid = crate::posix::ids::gettid();
                crate::arch::syscall::sys3(crate::internal::nr::TGKILL, pid as usize, tid as usize, signo as usize);
            }
        }
    }
}

// # C: int lio_listio64(int, struct aiocb64 *const[], int, struct sigevent*)
#[no_mangle]
pub unsafe extern "C" fn lio_listio64(mode: i32, list: *const *mut aiocb, nent: i32, sig: *mut sigevent) -> i32 {
    // SAFETY: aiocb64 == aiocb on LP64 (off64_t == off_t); identical contract,
    // forwards the caller's list/sigevent pointers straight to lio_listio.
    unsafe { lio_listio(mode, list, nent, sig) }
}
