//! aio — POSIX asynchronous I/O `<aio.h>` (docs/59§6 G17). Each aio_read/
//! aio_write enqueues a request serviced by a detached pthread worker that
//! does pread/pwrite at aio_offset and stores result/errno back into the
//! aiocb. aio_error reads the status (EINPROGRESS/0/errno), aio_return
//! harvests the byte count, aio_suspend blocks on a global cond until any
//! listed request completes. struct aiocb / aiocb64 byte layout matches host
//! `/usr/include/aio.h` (168 bytes, sigevent@32, aio_offset@128).
//!
//! Whole module is C-ABI exports + a pthread worker; built only into the
//! shipped freestanding artifact.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
pub mod ctl;
pub mod list;

use crate::pthread::cond::{pthread_cond_broadcast, pthread_cond_init, pthread_cond_t};
use crate::pthread::mutex::{pthread_mutex_lock, pthread_mutex_t, pthread_mutex_unlock};
use crate::pthread::{pthread_create, pthread_detach};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

// aio_lio_opcode values (host <aio.h>).
pub(crate) const LIO_READ: i32 = 0;
pub(crate) const LIO_WRITE: i32 = 1;
pub(crate) const LIO_NOP: i32 = 2;

// errno values used by aio (host <asm-generic/errno.h>).
pub(crate) const EINPROGRESS: i32 = 115;
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ECANCELED: i32 = 125;
pub(crate) const EAGAIN: i32 = 11;

// sigev_notify values (host <bits/sigevent-consts.h>).
pub(crate) const SIGEV_SIGNAL: i32 = 0;
pub(crate) const SIGEV_NONE: i32 = 1;
pub(crate) const SIGEV_THREAD: i32 = 2;

/// `union sigval` — layout-identical to host (`int` / `void*` overlay, 8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub union sigval {
    pub sival_int: i32,
    pub sival_ptr: *mut c_void,
}

/// `struct sigevent` — 64-byte layout matching host `bits/types/sigevent_t.h`.
#[repr(C)]
pub struct sigevent {
    pub sigev_value: sigval,
    pub sigev_signo: i32,
    pub sigev_notify: i32,
    // _sigev_un: { int _pad[12]; pid_t _tid; { void(*)(sigval); void* } }
    pub sigev_un: [usize; 6],
}
const _: () = assert!(core::mem::size_of::<sigevent>() == 64);

/// `struct aiocb` — 168-byte layout matching host `/usr/include/aio.h`.
/// `aiocb64` is byte-identical on LP64 (off64_t == off_t), so it is an alias.
#[repr(C)]
pub struct aiocb {
    pub aio_fildes: i32,         // @0  fd
    pub aio_lio_opcode: i32,     // @4  LIO_READ/WRITE/NOP
    pub aio_reqprio: i32,        // @8  priority offset (ignored)
    pub aio_buf: *mut c_void,    // @16 transfer buffer (volatile void* in C)
    pub aio_nbytes: usize,       // @24 transfer length
    pub aio_sigevent: sigevent,  // @32 completion notification (64 bytes)
    __next_prio: *mut c_void,    // @96  internal
    __abs_prio: i32,             // @104 internal
    __policy: i32,               // @108 internal
    __error_code: i32,           // @112 aio_error() result
    __return_value: isize,       // @120 aio_return() result
    pub aio_offset: i64,         // @128 file offset
    __glibc_reserved: [u8; 32],  // @136 reserved
}
const _: () = assert!(core::mem::size_of::<aiocb>() == 168);
const _: () = assert!(core::mem::offset_of!(aiocb, aio_sigevent) == 32);
const _: () = assert!(core::mem::offset_of!(aiocb, aio_offset) == 128);

/// `struct aioinit` — host GNU layout (8 ints, 32 bytes). All fields advisory.
#[repr(C)]
pub struct aioinit {
    pub aio_threads: i32,
    pub aio_num: i32,
    pub aio_locks: i32,
    pub aio_usedba: i32,
    pub aio_debug: i32,
    pub aio_numusers: i32,
    pub aio_idle_time: i32,
    pub aio_reserved: i32,
}

// Global completion lock + cond. A request publishes its result under LOCK,
// flips __error_code out of EINPROGRESS, then broadcasts COND. aio_suspend
// waits on COND. COND_READY guards a one-time pthread_cond_init. The lock/cond
// live in UnsafeCell wrappers (the libc static-shared-state pattern) rather
// than `static mut`, matching stdio's STDIN_FILE etc.
struct LockCell(core::cell::UnsafeCell<pthread_mutex_t>);
// SAFETY: a zeroed pthread_mutex_t is the valid NORMAL INITIALIZER; the futex
// inside it provides the cross-thread synchronization, so sharing the cell's
// address across threads is sound — that is the whole point of a process lock.
unsafe impl Sync for LockCell {}
struct CondCell(core::cell::UnsafeCell<pthread_cond_t>);
// SAFETY: a zeroed pthread_cond_t is the valid INITIALIZER; the seq-futex
// inside it synchronizes waiters/signalers, so the shared address is sound.
unsafe impl Sync for CondCell {}

// SAFETY: an all-zero pthread_mutex_t is exactly PTHREAD_MUTEX_INITIALIZER
// (NORMAL kind, __lock==0 free); zeroed() builds that valid initial state.
static LOCK: LockCell = LockCell(core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }));
// SAFETY: an all-zero pthread_cond_t is the valid cond INITIALIZER (seq==0,
// clock REALTIME); zeroed() builds that valid initial state.
static COND: CondCell = CondCell(core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }));
static COND_READY: AtomicU32 = AtomicU32::new(0);

pub(crate) unsafe fn completion_lock() -> *mut pthread_mutex_t {
    // SAFETY: one-time lazy init of the shared completion cond; the CAS elects
    // a single initializer, and a zeroed mutex/cond is already a valid
    // INITIALIZER, so concurrent first-callers see a usable lock. Returns the
    // stable cell address that all threads share.
    unsafe {
        if COND_READY.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            pthread_cond_init(COND.0.get(), core::ptr::null());
            COND_READY.store(2, Ordering::Release);
        }
        LOCK.0.get()
    }
}
pub(crate) unsafe fn completion_cond() -> *mut pthread_cond_t {
    // SAFETY: COND is zero-initialized (valid INITIALIZER) and published by
    // completion_lock() before any waiter parks; returns its stable address.
    COND.0.get()
}

// Worker argument: the aiocb pointer, transported across the thread boundary.
struct Job(*mut aiocb);
// SAFETY: the aiocb outlives the worker (caller owns it until aio_return);
// only one worker ever touches a given aiocb, so the pointer is not aliased.
unsafe impl Send for Job {}

// Publish a completed result into the aiocb and wake suspenders.
pub(crate) unsafe fn publish(cb: *mut aiocb, err: i32, ret: isize) {
    // SAFETY: cb is the live aiocb owned by this request's worker; storing
    // __return_value before __error_code under the lock gives readers a
    // consistent view once aio_error() no longer reports EINPROGRESS.
    unsafe {
        let l = completion_lock();
        pthread_mutex_lock(l);
        (*cb).__return_value = ret;
        (*cb).__error_code = err;
        pthread_cond_broadcast(completion_cond());
        pthread_mutex_unlock(l);
    }
}

pub(crate) unsafe fn set_inprogress(cb: *mut aiocb) {
    // SAFETY: cb is a writable aiocb supplied by the caller; mark it queued.
    unsafe { (*cb).__error_code = EINPROGRESS; (*cb).__return_value = -1; }
}
pub(crate) unsafe fn error_of(cb: *const aiocb) -> i32 {
    // SAFETY: cb points at a live aiocb; reading the status word is the
    // aio_error contract (EINPROGRESS while queued, then 0/errno).
    unsafe { (*cb).__error_code }
}
pub(crate) unsafe fn return_of(cb: *const aiocb) -> isize {
    // SAFETY: cb points at a completed aiocb; harvest the stored byte count.
    unsafe { (*cb).__return_value }
}
pub(crate) unsafe fn opcode_of(cb: *const aiocb) -> i32 {
    // SAFETY: cb is a live aiocb; aio_lio_opcode is a plain i32 field.
    unsafe { (*cb).aio_lio_opcode }
}

// Worker entry: perform the I/O for the opcode, publish, then fire the
// completion notification per aio_sigevent.
extern "C" fn worker(arg: *mut c_void) -> *mut c_void {
    // SAFETY: arg is the boxed Job holding the request's aiocb; we own it for
    // the duration of this worker and free the box before returning.
    unsafe {
        let job = alloc::boxed::Box::from_raw(arg as *mut Job);
        let cb = job.0;
        let fd = (*cb).aio_fildes;
        let buf = (*cb).aio_buf as *mut u8;
        let n = (*cb).aio_nbytes;
        let off = (*cb).aio_offset;
        let (err, ret) = match opcode_of(cb) {
            x if x == LIO_NOP => (0, 0isize),
            x if x == LIO_WRITE => io_result(crate::posix::io::pwrite(fd, buf as *const u8, n, off)),
            _ => io_result(crate::posix::io::pread(fd, buf, n, off)),
        };
        publish(cb, err, ret);
        notify(cb);
    }
    core::ptr::null_mut()
}

// A pread/pwrite return splits into (aio_error, aio_return): -1 carries errno
// in the thread's errno slot, success is the byte count with error 0.
unsafe fn io_result(r: isize) -> (i32, isize) {
    // SAFETY: r is the libc pread/pwrite return; on -1 the worker thread's
    // errno slot (via __errno_location) holds the failure code.
    if r < 0 { (unsafe { *crate::internal::errno::__errno_location() }, -1) } else { (0, r) }
}

// Completion notification (SIGEV_NONE = nothing; SIGEV_SIGNAL = tgkill self;
// SIGEV_THREAD = spawn the notify function). Best-effort per POSIX.
unsafe fn notify(cb: *mut aiocb) {
    // SAFETY: cb is the just-completed aiocb; aio_sigevent is a 64-byte struct
    // whose sigev_notify selects the (optional) notification path below.
    unsafe {
        let ev = core::ptr::addr_of!((*cb).aio_sigevent);
        match (*ev).sigev_notify {
            x if x == SIGEV_SIGNAL => {
                let signo = (*ev).sigev_signo;
                if signo > 0 {
                    let pid = crate::posix::io::getpid();
                    let tid = crate::posix::ids::gettid();
                    crate::arch::syscall::sys3(crate::internal::nr::TGKILL, pid as usize, tid as usize, signo as usize);
                }
            }
            x if x == SIGEV_THREAD => {
                let f = (*ev).sigev_un[0];
                if f != 0 {
                    let g = alloc::boxed::Box::new(ThreadNotify { func: f, val: (*ev).sigev_value });
                    let mut tid = 0usize;
                    if pthread_create(&mut tid, core::ptr::null(), thread_notify_trampoline, alloc::boxed::Box::into_raw(g) as *mut c_void) == 0 {
                        pthread_detach(tid);
                    }
                }
            }
            _ => {} // SIGEV_NONE
        }
    }
}

struct ThreadNotify { func: usize, val: sigval }
// SAFETY: the box is handed to exactly one notify thread which consumes it.
unsafe impl Send for ThreadNotify {}

extern "C" fn thread_notify_trampoline(arg: *mut c_void) -> *mut c_void {
    // SAFETY: arg is the boxed ThreadNotify created in notify(); reconstruct,
    // call the user's void(*)(union sigval) with the stored value, then drop.
    unsafe {
        let g = alloc::boxed::Box::from_raw(arg as *mut ThreadNotify);
        let f: extern "C" fn(sigval) = core::mem::transmute(g.func);
        f(g.val);
    }
    core::ptr::null_mut()
}

// Enqueue: validate, mark in-progress, spawn a detached worker. opcode is
// LIO_READ/LIO_WRITE/LIO_NOP (stamped into aio_lio_opcode before enqueue).
pub(crate) unsafe fn enqueue(cb: *mut aiocb, opcode: i32) -> i32 {
    // SAFETY: cb is a caller-owned aiocb valid until aio_return; we stamp the
    // opcode, mark it queued, and box its pointer for the worker thread.
    unsafe {
        if cb.is_null() { crate::internal::errno::set(EINVAL); return -1; }
        (*cb).aio_lio_opcode = opcode;
        let _ = completion_lock(); // ensure cond initialised before any wait
        set_inprogress(cb);
        let job = alloc::boxed::Box::new(Job(cb));
        let mut tid = 0usize;
        if pthread_create(&mut tid, core::ptr::null(), worker, alloc::boxed::Box::into_raw(job) as *mut c_void) != 0 {
            publish(cb, EAGAIN, -1);
            crate::internal::errno::set(EAGAIN);
            return -1;
        }
        pthread_detach(tid);
        0
    }
}

// # C: int aio_read(struct aiocb *aiocbp)
#[no_mangle]
pub unsafe extern "C" fn aio_read(cb: *mut aiocb) -> i32 {
    // SAFETY: cb is a caller-owned aiocb; enqueue a LIO_READ worker against it.
    unsafe { enqueue(cb, LIO_READ) }
}
// # C: int aio_write(struct aiocb *aiocbp)
#[no_mangle]
pub unsafe extern "C" fn aio_write(cb: *mut aiocb) -> i32 {
    // SAFETY: cb is a caller-owned aiocb; enqueue a LIO_WRITE worker against it.
    unsafe { enqueue(cb, LIO_WRITE) }
}

// # C: int aio_read64(struct aiocb64 *) — LFS alias; aiocb64 == aiocb on LP64.
// SAFETY: identical layout/contract to aio_read on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_read64(cb: *mut aiocb) -> i32 { unsafe { aio_read(cb) } }
// # C: int aio_write64(struct aiocb64 *) — LFS alias.
// SAFETY: identical layout/contract to aio_write on LP64; forwards.
#[no_mangle] pub unsafe extern "C" fn aio_write64(cb: *mut aiocb) -> i32 { unsafe { aio_write(cb) } }

// # C: void aio_init(const struct aioinit *init) — advisory tuning; no-op
// (workers are spawned per request, so thread-count hints do not apply).
#[no_mangle]
pub unsafe extern "C" fn aio_init(_init: *const aioinit) {
    // SAFETY: init is read-only and ignored; the per-request worker model has
    // no preallocated pool to size, so this records nothing.
}
