// Which entries cannot finish inside the submission that issued them, and what
// preparing one costs the submitter.
//
// Two kinds of entry are deferred. Some can never run inline — a timeout has
// nothing to do but wait, and a poll's whole job is to wait — and some are
// deferred because the submitter said so with `IOSQE_ASYNC`. Everything else
// still runs inline first and only defers if the description it names would
// have made it block.
//
// Preparation happens HERE, in the submitting task, never on the worker: a
// timeout's timespec and a cancellation's key live in the submitter's address
// space, and a worker reading them later would read them out of whatever
// address space it happened to be borrowing.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring_abi::ops::*;
use crate::io_uring_sqe::Sqe;

use super::req::IoReq;

/// What arming a deferred request did.
pub enum Armed {
    /// It is waiting on a clock or a description; nothing more to do.
    Waiting,
    /// It needs a worker.
    Queue,
    /// It could not be armed at all.
    Failed(Errno),
}

/// Whether this opcode can only ever be deferred. # C: O(1)
pub fn always_async(op: u8) -> bool {
    matches!(op, IORING_OP_TIMEOUT | IORING_OP_LINK_TIMEOUT | IORING_OP_POLL_ADD)
}

/// Whether the submitter asked for this entry to be handed to a worker
/// regardless of whether it would have run inline. # C: O(1)
pub fn forced_async(flags: u8) -> bool { flags & IOSQE_ASYNC != 0 }

/// Whether this entry is deferred before it is ever attempted. # C: O(1)
pub fn defers(sqe: &Sqe) -> bool { always_async(sqe.opcode) || forced_async(sqe.flags) }

/// Read whatever an entry needs out of the submitter's address space before it
/// leaves the submitting task. # C: O(1)
pub fn prepare(req: &Arc<IoReq>) -> Result<(), Errno> {
    match req.sqe.opcode {
        IORING_OP_TIMEOUT => super::timeout::prepare(req, false),
        IORING_OP_LINK_TIMEOUT => super::timeout::prepare(req, true),
        IORING_OP_POLL_ADD => super::poll::prepare(req),
        _ => Ok(()),
    }
}

/// Put a prepared request into whatever state makes it wait. # C: O(1)
pub fn arm(req: &Arc<IoReq>) -> Armed {
    match req.sqe.opcode {
        IORING_OP_TIMEOUT => { super::timeout::arm(req); Armed::Waiting }
        // A link timeout is armed by the request it guards, not by the chain:
        // its clock must not start until the thing it is guarding does.
        IORING_OP_LINK_TIMEOUT => Armed::Waiting,
        IORING_OP_POLL_ADD => super::poll::arm(req),
        _ => Armed::Queue,
    }
}
