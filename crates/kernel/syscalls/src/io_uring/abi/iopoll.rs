// `IORING_SETUP_IOPOLL` — a ring whose completions are found by POLLING the
// backend rather than by waiting for it to interrupt.
//
// The whole flag is a property of the RING, never of one entry: userspace does
// not ask a single request to be polled. From the ring flag follow three
// decisions, and each of them is a different refusal a caller must be able to
// tell apart:
//
//   * which OPCODES a polled ring accepts at all — an opcode whose completion
//     cannot be found by polling would never complete on such a ring, so it is
//     `EINVAL` at submission, exactly as an unknown opcode is;
//   * which FILES a read or write on a polled ring may name — the transfer
//     must bypass the page cache (there is nothing to poll behind a cached
//     read) and the description's backend must actually expose a poll, which
//     is `EOPNOTSUPP`: the opcode was fine, this file cannot serve it;
//   * whether a caller may ask for high-priority completion on a ring that is
//     NOT polled, which is `EINVAL` — the ring would never poll for it.
//
// The wait side is a spin, not a sleep. `io_uring_enter` with
// `IORING_ENTER_GETEVENTS` on a polled ring drives the backend's poll in a
// loop until the caller's `min_complete` is reachable, and the loop is allowed
// to give up EARLY — with fewer completions than asked for, and success — in
// two cases the reference is explicit about: nothing is outstanding to poll
// (the request has not been issued yet, so spinning would spin forever), and
// the CPU is needed elsewhere. A caller of a polled ring is expected to call
// again; that is the contract, and a loop that instead spun until
// `min_complete` would hang the task.
//
// This kernel deviates from the reference in one respect, recorded in
// `scratch/known_issues.md`: the reference gives a polled ring its own
// hardware queues with no interrupt wired to them, so a poll races nothing.
// Here the queue polled is the same queue the interrupt drives, and the
// serialisation is the driver's own completion lock plus the claim-once
// completion — the same discipline that already makes the interrupt bottom
// half and a sleeping waiter safe against each other.

use syscall::errno::Errno;

use super::ops::*;

/// Whether a polled ring accepts this opcode — the reference's per-opcode
/// `iopoll` bit.
///
/// The set is small on purpose: the read/write family, whose completions a
/// backend poll can find, plus the entries that finish inside submission
/// (a no-op, the buffer and resource registrations, a cross-ring message) and
/// therefore need no poll to complete. Anything else on a polled ring is a
/// request whose completion nothing would ever look for. # C: O(1)
pub fn opcode_pollable(opcode: u8) -> bool {
    matches!(opcode,
        IORING_OP_NOP
        | IORING_OP_READV | IORING_OP_WRITEV
        | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED
        | IORING_OP_READ | IORING_OP_WRITE
        | IORING_OP_FILES_UPDATE
        | IORING_OP_PROVIDE_BUFFERS | IORING_OP_REMOVE_BUFFERS
        | IORING_OP_MSG_RING
        | IORING_OP_URING_CMD)
}

/// Submission admission for one entry against the ring's polled-ness.
///
/// `EINVAL`, not `EOPNOTSUPP`: on a polled ring the opcode is genuinely not a
/// legal entry, the same class of answer an out-of-range opcode gets. Reserving
/// `EOPNOTSUPP` for the file question below is what lets a caller tell "this
/// operation cannot be polled" from "this FILE cannot be polled" and fall back
/// to a different file rather than to a different ring. # C: O(1)
pub fn admit_opcode(ring_iopoll: bool, opcode: u8) -> Result<(), Errno> {
    if ring_iopoll && !opcode_pollable(opcode) { return Err(Errno::Einval); }
    Ok(())
}

/// What a read or write knows about its target when the polled-ring question
/// is decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RwTarget {
    /// The ring was created with `IORING_SETUP_IOPOLL`.
    pub ring_iopoll: bool,
    /// The transfer bypasses the page cache (`O_DIRECT`). A cached transfer
    /// has no outstanding device I/O for a poll to find.
    pub direct: bool,
    /// The description's backend exposes a poll for completed I/O at all —
    /// the reference's `file->f_op->iopoll != NULL`. This is a CAPABILITY, not
    /// a count: a backend that can be polled but has nothing ready right now
    /// is a completely different answer from one that can never be polled, and
    /// conflating them turns a hang into a wrong errno or the reverse.
    pub file_pollable: bool,
    /// The caller asked for high-priority completion on this transfer
    /// (`RWF_HIPRI`).
    pub hipri: bool,
}

/// The reference's `io_rw_init_file` ladder, both arms.
///
/// On a polled ring a transfer must be direct AND land on a pollable backend,
/// or nothing would ever look for its completion — `EOPNOTSUPP`. On an
/// ordinary ring a high-priority request is `EINVAL`, because a ring that does
/// not poll cannot honour it and silently downgrading it would leave the
/// caller believing it got a latency guarantee it did not. # C: O(1)
pub fn admit_rw(t: &RwTarget) -> Result<(), Errno> {
    if t.ring_iopoll {
        if !t.direct || !t.file_pollable { return Err(Errno::Eopnotsupp); }
        return Ok(());
    }
    if t.hipri { return Err(Errno::Einval); }
    Ok(())
}

/// Whether a polled read/write sets high-priority completion on its transfer.
/// It is derived from the RING, never taken from the entry: userspace does not
/// choose this per request. # C: O(1)
pub fn hipri_for(ring_iopoll: bool) -> bool { ring_iopoll }

// --- the wait loop ------------------------------------------------------

/// What the poll loop does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Drive the backend's poll once more. `oneshot` forbids the backend from
    /// busy-spinning inside a single call.
    Poll { oneshot: bool },
    /// Stop and report success with whatever was reaped, which may be less
    /// than the caller asked for.
    Stop,
    /// A signal arrived mid-spin: `EINTR`.
    Interrupted,
}

/// The decision made BEFORE the backend is touched at all.
///
/// `Some` means the loop never runs. A ring that lost a completion reports it
/// first, once — a caller told "0 completions" when one was destroyed would
/// wait forever for it. Completions already reapable end the call immediately:
/// the caller asked to be given events, and events exist, so there is nothing
/// to poll for. # C: O(1)
pub fn precheck(dropped: bool, events: u32) -> Option<Result<(), Errno>> {
    if dropped { return Some(Err(Errno::Ebadr)); }
    if events != 0 { return Some(Ok(())); }
    None
}

/// Whether one poll pass forbids the backend to spin.
///
/// Two independent reasons, and both are about not starving something else: a
/// caller asking for zero completions wants a look, not a wait; and once the
/// outstanding requests span more than one backend, spinning inside one of
/// them holds up every completion waiting on the others. # C: O(1)
pub fn oneshot(min_events: u32, multi_backend: bool) -> bool {
    min_events == 0 || multi_backend
}

/// The decision at the top of each loop pass.
///
/// Nothing outstanding is `Stop`, and it is the case that must not be got
/// wrong: a request handed to a worker has not reached its backend yet, so
/// there is nothing to poll, and a loop that kept spinning for it would never
/// exit. The reference breaks out of the loop here for exactly that reason and
/// reports success with fewer completions than asked for. # C: O(1)
pub fn before_poll(outstanding: u32, min_events: u32, multi_backend: bool) -> Step {
    if outstanding == 0 { return Step::Stop; }
    Step::Poll { oneshot: oneshot(min_events, multi_backend) }
}

/// The decision after one poll pass.
///
/// Order matters and is the reference's: a signal beats everything, then the
/// need to yield the CPU, then the caller's count. Checking the count first
/// would let a spinning caller sit on a processor through a pending `SIGKILL`.
/// # C: O(1)
pub fn after_poll(events: u32, min_events: u32, signal: bool, resched: bool) -> Step {
    if signal { return Step::Interrupted; }
    if resched { return Step::Stop; }
    if events >= min_events { return Step::Stop; }
    Step::Poll { oneshot: oneshot(min_events, false) }
}

#[cfg(test)]
#[path = "iopoll/tests.rs"]
mod tests;
