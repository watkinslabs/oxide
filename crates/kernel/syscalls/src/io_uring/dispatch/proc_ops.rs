// Operations that wait on something which is neither a file nor a clock: a
// futex word, or a child's state change.
//
// All three waiting forms are deferred before they are ever attempted (see
// `defer::always_async`), so the wait happens on a worker and never in the
// submitting task. That is not an optimisation: a submission holding two
// entries — a wait and the wake that satisfies it — would deadlock if the
// first ran inline, because the second would never be submitted. The wake side
// is not deferred, since it never waits.
//
// The operands come from `io_uring_abi::{futex_op, waitid_op}`, which is where
// the field ladder is testable; this file resolves nothing and decides
// nothing.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicI32, Ordering};

use crate::io_uring_abi::{futex_op, waitid_op};
use crate::io_uring::req::IoReq;

use super::super::defer::Armed;
use super::router::{call, Op};

fn err(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }

/// Private dispatch result: the callback fired but the futex value still
/// matched, so the request must register again without posting a CQE.
pub const FUTEX_REARM: i64 = i64::MIN + 0x2f;

struct FutexWaker { req: Weak<IoReq>, index: Arc<AtomicI32> }

impl ipc::live::futex::WaitCallback for FutexWaker {
    fn wake(&self, index: usize) {
        self.index.store(index as i32, Ordering::Release);
        if let Some(req) = self.req.upgrade() {
            if !req.is_done() { super::super::iowq::pool::WQ.queue(req); }
        }
    }
}

/// Arm one single-futex wait from the submitting task. The callback owns no
/// strong request reference, so an abandoned ring cannot be kept alive by the
/// futex key.
pub fn arm_futex_wait(req: &Arc<IoReq>) -> Armed {
    let f = match futex_op::prep(&req.sqe) { Ok(f) => f, Err(e) => return Armed::Failed(e) };
    let private = f.flags & ipc::futex2_flags::FUTEX2_PRIVATE != 0;
    let index = Arc::new(AtomicI32::new(-1));
    let callback = Arc::new(FutexWaker { req: Arc::downgrade(req), index: Arc::clone(&index) });
    match ipc::live::futex::register_callback(f.uaddr, f.val as u32, f.mask as u32,
                                               private, callback) {
        Ok(reg) => {
            let mut inner = req.inner.lock();
            inner.futex_wake_index = Some(index);
            inner.futex_wait = Some(reg);
            Armed::Waiting
        }
        Err(syscall::errno::Errno::Eagain) => Armed::Queue,
        Err(e) => Armed::Failed(e),
    }
}

/// Drop the current callback registration before a request is re-armed or
/// completed. `WaitRegistration::drop` removes only the matching callback.
pub fn disarm_futex_wait(req: &Arc<IoReq>) { req.inner.lock().futex_wait.take(); }

/// Park until the futex word changes, the bitset is woken, or the request is
/// cancelled. No timeout: an entry that wants one links a timeout to it, which
/// is the ring's own mechanism and the reason this operation has no timeout
/// field of its own. # C: O(1) park
pub fn futex_wait(op: &Op) -> i64 {
    let f = match futex_op::prep(op.sqe) { Ok(f) => f, Err(e) => return err(e) };
    match ipc::live::futex::callback_probe(f.uaddr, f.val as u32) {
        Ok(true) => 0,
        Ok(false) => FUTEX_REARM,
        Err(e) => err(e),
    }
}

pub fn futex_waitv_probe(req: &Arc<IoReq>) -> i64 {
    let inner = req.inner.lock();
    let Some(entries) = inner.futex_waitv.as_deref() else { return err(syscall::errno::Errno::Einval); };
    let preferred = inner.futex_wake_index.as_ref()
        .map(|i| i.load(Ordering::Acquire)).unwrap_or(-1);
    match ipc::live::futex::callback_probe_waitv(entries, preferred) {
        Ok(Some(index)) => index as i64,
        Ok(None) => FUTEX_REARM,
        Err(e) => err(e),
    }
}

pub fn arm_futex_waitv(req: &Arc<IoReq>) -> Armed {
    let f = match futex_op::prep_waitv(&req.sqe) { Ok(f) => f, Err(e) => return Armed::Failed(e) };
    let entries = match crate::futex_waitv::prepare_entries(f.uaddr, f.nr) {
        Ok(entries) => entries,
        Err(e) if e == syscall::errno::Errno::Eagain => return Armed::Queue,
        Err(e) => return Armed::Failed(e),
    };
    let index = Arc::new(AtomicI32::new(-1));
    let callback = Arc::new(FutexWaker { req: Arc::downgrade(req), index: Arc::clone(&index) });
    match ipc::live::futex::register_waitv_callback(&entries, callback) {
        Ok(reg) => {
            let mut inner = req.inner.lock();
            inner.futex_waitv = Some(entries);
            inner.futex_wake_index = Some(index);
            inner.futex_wait = Some(reg);
            Armed::Waiting
        }
        Err(syscall::errno::Errno::Eagain) => Armed::Queue,
        Err(e) => Armed::Failed(e),
    }
}

/// Wake up to `val` waiters whose bitset intersects `mask`. # C: O(waiters)
pub fn futex_wake(op: &Op) -> i64 {
    let f = match futex_op::prep(op.sqe) { Ok(f) => f, Err(e) => return err(e) };
    call(crate::s454_futex_wake::sys_futex_wake,
         [f.uaddr, f.mask, f.val, f.flags as u64, 0, 0])
}

/// Park until ANY of the named futexes is woken, reporting which.
/// # C: O(N) enqueue
pub fn futex_waitv(op: &Op) -> i64 {
    let f = match futex_op::prep_waitv(op.sqe) { Ok(f) => f, Err(e) => return err(e) };
    call(crate::futex_waitv::sys_futex_waitv, [f.uaddr, f.nr as u64, 0, 0, 0, 0])
}

/// Wait for a child's state change. The entry has nowhere to carry a resource
/// usage record, so none is asked for — a pointer taken from a field meaning
/// something else would be written into whatever the caller had there.
/// # C: bounded by the child-event scan
pub fn waitid(op: &Op) -> i64 {
    let w = match waitid_op::prep(op.sqe) { Ok(w) => w, Err(e) => return err(e) };
    call(crate::waitid::sys_waitid,
         [w.which as u64, w.id as u32 as u64, w.infop, w.options as u64, 0, 0])
}
