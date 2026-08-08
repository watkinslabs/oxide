// The receive copy-fault transaction: the ONE place that says, for a receive
// that has already taken a message off a socket, in what order the answer
// reaches user memory and what each faulting step does to the call.
//
// Why one owner. A receive publishes four independent things into a buffer the
// caller supplies — payload, ancillary stream, source address, and the two
// msghdr writebacks — and each of them can fault. Before this module every
// family answered that question for itself, in its own order, and two of them
// disagreed with the rest. That is the split-source-of-truth shape: nothing is
// red when one family drifts, because no test names the composition.
//
// The order user memory is written in, for every family and both batch layers:
//
//   1. payload
//   2. control stream
//   3. source address (`msg_name`, whose length is published before its bytes)
//   4. `msg_flags`
//   5. `msg_controllen`
//
// What each fault does:
//
// - PAYLOAD, record transport (datagram, seqpacket, error-queue record): the
//   receive reports EFAULT even though a prefix of the record landed in user
//   memory, and the record is RETIRED anyway — the transport dequeued it
//   before the copy, and a fault is not a reason to re-expose it. Only
//   `MSG_PEEK`, which never dequeues, leaves it readable.
// - PAYLOAD, stream transport: bytes are consumed exactly as far as they were
//   copied. A fault with a prefix already copied reports the prefix and leaves
//   the rest queued; a fault with nothing copied reports EFAULT.
// - CONTROL: never fails the receive. The entries that landed keep their
//   space, the faulting entry and everything after it contribute nothing, and
//   the published `msg_controllen` is exactly the prefix that landed.
// - NAME, `msg_flags`, `msg_controllen`: EFAULT. The message stays consumed —
//   a receive is not rolled back because the caller's header was unwritable —
//   and no later step runs, so a name fault leaves `msg_flags` and
//   `msg_controllen` untouched.
//
// Ungated on purpose: every receive slot file is
// `#[cfg(target_os = "oxide-kernel")]`, so a rule left in one of them has no
// test that can fail.

use crate::recv_control::{Control, ControlCopy};
use crate::recv_user::RecvUser;

/// How the transport underneath this receive treats a partly-copied payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transport {
    /// One message is one indivisible unit: a short copy fails the receive and
    /// retires the record.
    Record,
    /// A byte stream: the consumed length is whatever landed.
    Stream,
}

/// What a payload copy that could not place every byte reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PayloadFault {
    /// EFAULT; nothing of this message is readable again.
    Fail,
    /// Report the bytes that landed; the rest stays queued.
    Deliver(usize),
}

/// The payload rule, given the transport and how many bytes reached user
/// memory before the fault. # C: O(1)
pub(crate) fn payload_fault(transport: Transport, copied: usize) -> PayloadFault {
    match transport {
        Transport::Record => PayloadFault::Fail,
        Transport::Stream if copied != 0 => PayloadFault::Deliver(copied),
        Transport::Stream => PayloadFault::Fail,
    }
}

/// What a stream receive answers once one fragment could not be placed:
/// whatever earlier fragments delivered, or the fault itself. # C: O(1)
pub(crate) fn stream_result(delivered: usize, error: i64) -> Result<usize, i64> {
    match payload_fault(Transport::Stream, delivered) {
        PayloadFault::Deliver(n) => Ok(n),
        PayloadFault::Fail => Err(error),
    }
}

/// What a record receive answers when its message could not be placed whole.
/// # C: O(1)
pub(crate) fn record_result(placed: usize, error: i64) -> Result<usize, i64> {
    match payload_fault(Transport::Record, placed) {
        PayloadFault::Deliver(n) => Ok(n),
        PayloadFault::Fail => Err(error),
    }
}

/// The `msg_controllen` a control stream publishes. A faulting entry does not
/// fail the receive and does not advance the cursor. # C: O(1)
pub(crate) fn control_len(copy: ControlCopy) -> usize { copy.copied }

/// Publish one delivered message's control, address and header writebacks in
/// the one order every family uses, and hand back what the receive returns.
///
/// `success` is the value the call reports when nothing faults. `extra_flags`
/// are the per-family output bits (`MSG_TRUNC`, `MSG_EOR`, `MSG_ERRQUEUE`,
/// `MSG_OOB`, the preserved input bits) that this receive settled before the
/// control stream ran. # C: O(control + name + faults)
pub(crate) fn publish(user: &RecvUser, control: &mut Control, name: &[u8], extra_flags: u32,
    success: i64) -> i64
{
    let len = control.copy_to_recv(user);
    let flags = extra_flags | control.flags;
    if let Err(error) = user.copy_name(name) { return error; }
    if let Err(error) = user.finish(len, flags) { return error; }
    success
}

/// The same publication for a family that builds no control stream of its own
/// but has already settled a length and flags (`SCM_RIGHTS` delivery does its
/// own fd installation before this point). # C: O(name + faults)
pub(crate) fn publish_settled(user: &RecvUser, control_len: usize, name: &[u8], flags: u32,
    success: i64) -> i64
{
    if let Err(error) = user.copy_name(name) { return error; }
    if let Err(error) = user.finish(control_len, flags) { return error; }
    success
}

#[cfg(test)]
mod tests;
