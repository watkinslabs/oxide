// Which entries can never run inside the submission that issued them.
//
// Three reasons put an opcode here. A timeout and a poll have nothing to do
// but wait. A driver command is completed by the driver, not by the
// submission. And an operation that PARKS — on a futex word, on a child, on an
// epoll set — must never park the SUBMITTING task: a submission holding a wait
// and the wake that satisfies it would deadlock, because the wake would never
// be submitted. A splice is deferred for its own reason: it moves an unbounded
// number of bytes between two descriptions, either of which may block, so it
// belongs on a worker whatever the submitter asked for.
//
// Ungated: this is the decision, and `io_uring/defer.rs` — which holds it in
// the engine — is kernel-gated by way of `kernel_body.rs`, so a test left
// beside it there would compile out silently (CLAUDE.md phantom-test rule).

use crate::io_uring_sqe::Sqe;

use super::ops::*;

/// Whether this opcode can only ever be deferred. # C: O(1)
pub fn always_async(op: u8) -> bool {
    matches!(op, IORING_OP_TIMEOUT | IORING_OP_LINK_TIMEOUT | IORING_OP_POLL_ADD
        | IORING_OP_URING_CMD | IORING_OP_URING_CMD128
        | IORING_OP_SPLICE | IORING_OP_TEE
        | IORING_OP_WAITID | IORING_OP_FUTEX_WAIT | IORING_OP_FUTEX_WAITV
        | IORING_OP_EPOLL_WAIT)
}

/// Whether the submitter asked for this entry to be handed to a worker
/// regardless of whether it would have run inline. # C: O(1)
pub fn forced_async(flags: u8) -> bool { flags & IOSQE_ASYNC != 0 }

/// Whether this entry is deferred before it is ever attempted. # C: O(1)
pub fn defers(sqe: &Sqe) -> bool {
    always_async(sqe.opcode) || forced_async(sqe.flags)
        || super::recvsend::defers_before_issue(sqe.opcode, sqe.flags, sqe.ioprio)
}

#[cfg(test)]
#[path = "async_policy/tests.rs"]
mod tests;
