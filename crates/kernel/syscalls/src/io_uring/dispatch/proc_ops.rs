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

use crate::io_uring_abi::{futex_op, waitid_op};

use super::router::{call, Op};

fn err(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }

/// Park until the futex word changes, the bitset is woken, or the request is
/// cancelled. No timeout: an entry that wants one links a timeout to it, which
/// is the ring's own mechanism and the reason this operation has no timeout
/// field of its own. # C: O(1) park
pub fn futex_wait(op: &Op) -> i64 {
    let f = match futex_op::prep(op.sqe) { Ok(f) => f, Err(e) => return err(e) };
    call(crate::s455_futex_wait::sys_futex_wait,
         [f.uaddr, f.val, f.mask, f.flags as u64, 0, 0])
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
