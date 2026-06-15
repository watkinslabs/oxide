// aio status/control: aio_error, aio_return, aio_suspend, aio_cancel,
// aio_fsync (+ the `64` LFS aliases). docs/59§6 G17.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
use super::{aiocb, completion_cond, completion_lock, error_of, opcode_of, publish, return_of, EINPROGRESS, EINVAL};
use crate::internal::errno::set;
use crate::pthread::cond::{pthread_cond_timedwait, pthread_cond_wait};
use crate::pthread::mutex::{pthread_mutex_lock, pthread_mutex_unlock};
use crate::time::clock::timespec;
use core::ffi::c_void;

// aio_cancel return values (host <aio.h> enum). AIO_CANCELED (0) is never
// returned: dispatched workers are not preemptible.
const AIO_NOTCANCELED: i32 = 1;
const AIO_ALLDONE: i32 = 2;
// aio_fsync operation must be O_SYNC or O_DSYNC.
const O_DSYNC: i32 = 0o10000;
const O_SYNC: i32 = 0o4010000;

// # C: int aio_error(const struct aiocb *aiocbp)
#[no_mangle]
pub unsafe extern "C" fn aio_error(cb: *const aiocb) -> i32 {
    // SAFETY: cb is a caller-owned aiocb previously passed to aio_*; read its
    // status word under the completion lock for a coherent view.
    unsafe {
        if cb.is_null() { set(EINVAL); return -1; }
        let l = completion_lock();
        pthread_mutex_lock(l);
        let e = error_of(cb);
        pthread_mutex_unlock(l);
        e
    }
}

// # C: ssize_t aio_return(struct aiocb *aiocbp)
#[no_mangle]
pub unsafe extern "C" fn aio_return(cb: *mut aiocb) -> isize {
    // SAFETY: cb is a completed aiocb; harvest its stored byte count. Calling
    // before completion is UB per POSIX; we return the in-progress sentinel.
    unsafe {
        if cb.is_null() { set(EINVAL); return -1; }
        let l = completion_lock();
        pthread_mutex_lock(l);
        let r = return_of(cb);
        pthread_mutex_unlock(l);
        r
    }
}

// # C: int aio_suspend(const struct aiocb *const list[], int nent,
//                      const struct timespec *timeout)
#[no_mangle]
pub unsafe extern "C" fn aio_suspend(list: *const *const aiocb, nent: i32, timeout: *const timespec) -> i32 {
    // SAFETY: list is a caller array of nent aiocb pointers (some may be NULL,
    // skipped per POSIX); we park on the completion cond until any non-NULL
    // entry leaves EINPROGRESS, or the (relative) timeout elapses.
    unsafe {
        if list.is_null() || nent < 0 { set(EINVAL); return -1; }
        // Convert a relative timeout into an absolute REALTIME deadline once.
        let mut abs = timespec { tv_sec: 0, tv_nsec: 0 };
        let have_to = !timeout.is_null();
        if have_to {
            crate::time::clock::clock_gettime(crate::time::clock::CLOCK_REALTIME, &mut abs);
            abs.tv_sec += (*timeout).tv_sec;
            abs.tv_nsec += (*timeout).tv_nsec;
            if abs.tv_nsec >= 1_000_000_000 { abs.tv_nsec -= 1_000_000_000; abs.tv_sec += 1; }
        }
        let l = completion_lock();
        pthread_mutex_lock(l);
        loop {
            let mut any = false;
            for i in 0..nent as isize {
                let cb = *list.offset(i);
                if !cb.is_null() && error_of(cb) != EINPROGRESS { any = true; break; }
            }
            if any { pthread_mutex_unlock(l); return 0; }
            let rc = if have_to {
                pthread_cond_timedwait(completion_cond(), l, &abs)
            } else {
                pthread_cond_wait(completion_cond(), l)
            };
            if rc != 0 { // ETIMEDOUT
                pthread_mutex_unlock(l);
                set(super::EAGAIN); // POSIX: aio_suspend timeout sets EAGAIN
                return -1;
            }
        }
    }
}

// # C: int aio_cancel(int fildes, struct aiocb *aiocbp)
#[no_mangle]
pub unsafe extern "C" fn aio_cancel(_fildes: i32, cb: *mut aiocb) -> i32 {
    // SAFETY: cb is NULL (cancel all for fd) or a caller-owned aiocb. Workers
    // are not preemptible once dispatched, so an in-progress request reports
    // NOTCANCELED and a completed one ALLDONE — both POSIX-conformant.
    unsafe {
        if cb.is_null() { return AIO_NOTCANCELED; }
        if opcode_of(cb) == super::LIO_NOP { return AIO_ALLDONE; }
        let l = completion_lock();
        pthread_mutex_lock(l);
        let e = error_of(cb);
        let r = if e == EINPROGRESS { AIO_NOTCANCELED } else { AIO_ALLDONE };
        pthread_mutex_unlock(l);
        r
    }
}

// # C: int aio_fsync(int op, struct aiocb *aiocbp)
#[no_mangle]
pub unsafe extern "C" fn aio_fsync(op: i32, cb: *mut aiocb) -> i32 {
    // SAFETY: cb is a caller-owned aiocb naming aio_fildes; enqueue a sync
    // request whose worker runs fsync/fdatasync on that fd at completion.
    unsafe {
        if cb.is_null() || (op != O_SYNC && op != O_DSYNC) { set(EINVAL); return -1; }
        super::set_inprogress(cb);
        let datasync = op == O_DSYNC;
        let g = alloc::boxed::Box::new(FsyncJob { cb, datasync });
        let mut tid = 0usize;
        let _ = super::completion_lock();
        if crate::pthread::pthread_create(&mut tid, core::ptr::null(), fsync_worker, alloc::boxed::Box::into_raw(g) as *mut c_void) != 0 {
            publish(cb, super::EAGAIN, -1);
            set(super::EAGAIN);
            return -1;
        }
        crate::pthread::pthread_detach(tid);
        0
    }
}

struct FsyncJob { cb: *mut aiocb, datasync: bool }
// SAFETY: the box is consumed by exactly one fsync worker thread.
unsafe impl Send for FsyncJob {}

extern "C" fn fsync_worker(arg: *mut c_void) -> *mut c_void {
    // SAFETY: arg is the boxed FsyncJob; run the chosen sync syscall on the
    // aiocb's fd, publish the result, then free the box.
    unsafe {
        let g = alloc::boxed::Box::from_raw(arg as *mut FsyncJob);
        let fd = (*g.cb).aio_fildes;
        let nr = if g.datasync { crate::internal::nr::FDATASYNC } else { crate::internal::nr::FSYNC };
        let r = crate::arch::syscall::sys1(nr, fd as usize);
        let (err, ret) = if r < 0 { (-r as i32, -1) } else { (0, 0) };
        publish(g.cb, err, ret);
    }
    core::ptr::null_mut()
}

// LFS aliases — aiocb64 == aiocb on LP64, off64_t == off_t. Forwards.
// # C: int aio_error64(const struct aiocb64 *)
// SAFETY: identical layout/contract on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_error64(cb: *const aiocb) -> i32 { unsafe { aio_error(cb) } }
// # C: ssize_t aio_return64(struct aiocb64 *)
// SAFETY: identical layout/contract on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_return64(cb: *mut aiocb) -> isize { unsafe { aio_return(cb) } }
// # C: int aio_suspend64(const struct aiocb64 *const[], int, const struct timespec*)
// SAFETY: identical layout/contract on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_suspend64(list: *const *const aiocb, nent: i32, to: *const timespec) -> i32 { unsafe { aio_suspend(list, nent, to) } }
// # C: int aio_cancel64(int, struct aiocb64 *)
// SAFETY: identical layout/contract on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_cancel64(fildes: i32, cb: *mut aiocb) -> i32 { unsafe { aio_cancel(fildes, cb) } }
// # C: int aio_fsync64(int, struct aiocb64 *)
// SAFETY: identical layout/contract on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_fsync64(op: i32, cb: *mut aiocb) -> i32 { unsafe { aio_fsync(op, cb) } }
