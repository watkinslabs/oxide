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
// A polled transfer is SUBMIT-THEN-POLL: it is issued to its backend and
// returns with no completion posted, and `io_uring_enter` with
// `IORING_ENTER_GETEVENTS` is what finishes it. That is the reference's
// `-EIOCBQUEUED` arm, and without it the flag pays for nothing — a transfer
// that has already posted its result is not one a poll can find.
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
// `IORING_SETUP_HYBRID_IOPOLL` sleeps for part of a transfer's expected
// service time before it starts spinning. The estimate is the ring's own
// running MINIMUM of observed service times, not a block-layer statistic: a
// transfer is stamped when it is issued, each poll pass folds what it observed
// back in, and the next transfer sleeps for half of it.
//
// This kernel deviates from the reference in one respect, recorded in
// `scratch/known_issues.md`: the reference gives a polled ring its own
// hardware queues with no interrupt wired to them, so a poll races nothing and
// a polled transfer costs no interrupt. Here the queue polled is the same queue
// the interrupt drives, and the serialisation is the driver's own completion
// lock plus the claim-once completion — the same discipline that already makes
// the interrupt bottom half and a sleeping waiter safe against each other. The
// difference is a cost, not a correctness gap: the completion is found either
// way.

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

// --- submit-then-poll ---------------------------------------------------

/// The SQE offset meaning "use the description's own file position".
pub const CUR_POS: u64 = u64::MAX;

/// Whether this entry takes the submit-then-poll path: issued to the backend,
/// returning with NO completion posted, and completed later by the poll.
///
/// Only the transfer family, and only on a polled ring. Everything else on
/// such a ring finishes inside the submission that issued it — a no-op, a
/// buffer registration, a cross-ring message — and a completion that has
/// already been posted is not one a poll can find. That was the whole reason
/// the poll loop paid for nothing: the transfers were finishing inline too, so
/// the loop only ever ran for work a worker happened to be holding.
///
/// `off == -1` — "use the description's own position" — is excluded, and that
/// exclusion is load-bearing rather than a shortcut: the position belongs to
/// the DESCRIPTION, so two queued transfers naming it would both read the same
/// value and both advance it, and there is no moment at which either could
/// take it exclusively. Such an entry keeps the ordinary path, where the
/// position is read and advanced inside one operation. # C: O(1)
pub fn defers_to_backend(ring_iopoll: bool, opcode: u8, off: u64) -> bool {
    if !ring_iopoll { return false; }
    if off == CUR_POS { return false; }
    matches!(opcode,
        IORING_OP_READ | IORING_OP_WRITE
        | IORING_OP_READV | IORING_OP_WRITEV
        | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED)
}

/// Whether this opcode moves bytes OUT of the caller's buffer. # C: O(1)
pub fn is_write(opcode: u8) -> bool {
    matches!(opcode, IORING_OP_WRITE | IORING_OP_WRITEV | IORING_OP_WRITE_FIXED)
}

/// The result a completed transfer's CQE carries.
///
/// A write reports what the DEVICE took: the payload left the caller's buffer
/// at submission, so where it went afterwards is the device's answer alone. A
/// read reports what LANDED in the caller's buffer, which is not always what
/// the device delivered — the destination is written after the fact, and a page
/// that has since been unmapped takes fewer bytes than were offered. Reporting
/// the device's count there would tell a caller its buffer holds data that is
/// not in it.
///
/// A read that delivered bytes and landed none is `EFAULT` rather than a
/// zero-length read: zero means end-of-file, and a caller that treated a failed
/// copy as EOF would stop reading a file it had barely started. # C: O(1)
pub fn completed_res(write: bool, delivered: usize, landed: usize) -> i64 {
    if write { return delivered as i64; }
    if delivered != 0 && landed == 0 { return -(Errno::Efault.as_i32() as i64); }
    landed as i64
}

// --- `IORING_SETUP_HYBRID_IOPOLL` ---------------------------------------

/// No transfer has been timed yet, so there is nothing to sleep against.
/// Sentinel rather than an `Option` because it is also the identity for the
/// running minimum below: an unknown estimate loses to every real one.
pub const NO_ESTIMATE: u64 = u64::MAX;

/// How long a hybrid-polled transfer sleeps before it starts spinning.
///
/// Half the ring's current estimate, which is the reference's fraction. Two
/// cases sleep for nothing at all and both matter: a ring that has never timed
/// a transfer has no estimate to halve, and a request that has ALREADY slept
/// once in an earlier pass must not sleep again — the sleep is meant to skip
/// the front of one transfer's service time, not to be paid once per poll
/// pass, and re-paying it would make a slow device slower the more often it
/// was polled. # C: O(1)
pub fn hybrid_sleep_ns(estimate: u64, slept_already: bool) -> u64 {
    if slept_already { return 0; }
    if estimate == NO_ESTIMATE { return 0; }
    estimate / 2
}

/// Fold one observed service time into the ring's estimate.
///
/// The MINIMUM, not an average, and the reference is explicit about why: the
/// ring may be polling backends of different speeds, and sleeping for longer
/// than the fastest of them takes would hold back completions that were ready.
/// An estimate that is too small only costs spinning, which is what the mode is
/// for; one that is too large loses completions to sleep. # C: O(1)
pub fn observe_runtime(estimate: u64, runtime: u64) -> u64 {
    if runtime < estimate { runtime } else { estimate }
}

/// The service time one poll pass observed: elapsed since the transfer was
/// issued, LESS whatever this pass spent asleep.
///
/// Subtracting the sleep is what keeps the estimate from ratcheting: an
/// estimate that counted its own sleep would grow by half of itself every pass
/// until the mode was a pure sleep. Saturating, because a clock that appears to
/// go backwards must yield zero rather than an enormous estimate. # C: O(1)
pub fn hybrid_runtime(now: u64, issued_at: u64, slept: u64) -> u64 {
    now.saturating_sub(issued_at).saturating_sub(slept)
}

/// The errno a refused direct submission reports.
///
/// A queued transfer is refused before it reaches the device for exactly two
/// reasons, and a caller acts differently on each: the request was not whole
/// blocks, which is `EINVAL` and stays wrong however often it is retried, or it
/// started past the end of the device, which is `ENOSPC` and is a fact about
/// the device rather than the request. Anything else a backend invents is an
/// I/O error, because the transfer neither ran nor was well-formed enough to
/// name a better answer. # C: O(1)
pub fn submit_errno(e: vfs::VfsError) -> Errno {
    match e {
        vfs::VfsError::Einval => Errno::Einval,
        vfs::VfsError::Enospc => Errno::Enospc,
        vfs::VfsError::Ebadf  => Errno::Ebadf,
        vfs::VfsError::Enxio  => Errno::Enxio,
        vfs::VfsError::Enomem => Errno::Enomem,
        vfs::VfsError::Eopnotsupp => Errno::Eopnotsupp,
        _ => Errno::Eio,
    }
}

/// What a poll pass does with one request it finds in the polled set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReapStep {
    /// Leave it alone: it has no queued transfer, its backend has not
    /// finished, or somebody else has already taken it.
    Skip,
    /// Take it: this pass owns its completion, and no other path may post one.
    Take,
}

/// Whether this pass completes the request.
///
/// `claimed` is the result of the one compare-exchange that decides ownership,
/// so it is asked LAST — a pass that asked it first would take a request whose
/// backend has not finished, and the transfer's result would be lost. A
/// request a cancellation already claimed is skipped here and its backend's
/// later completion fills a slot nobody reads, which is what makes exactly one
/// completion per request true whichever path gets there first. # C: O(1)
pub fn reap_step(has_queued: bool, backend_done: bool, claimed: bool) -> ReapStep {
    if !has_queued || !backend_done || !claimed { return ReapStep::Skip; }
    ReapStep::Take
}

/// Walk a completed read's bytes across the caller's segments, in order, and
/// report how many landed.
///
/// `put` is handed a segment address, the offset into the transfer's bytes
/// that run starts at, and its length; it writes the run and returns how many
/// bytes of it actually reached the caller. A short write ends the walk: the segments past a page the caller
/// does not have mapped are not reachable either, and reporting the whole
/// length would tell the caller it read bytes that are not in its buffer.
///
/// The walk is stated here, away from the address space it writes into,
/// because the arithmetic is what can be wrong: a segment longer than the
/// bytes left, a zero-length segment in the middle, a caller whose segments
/// total more than the transfer returned. # C: O(N_segs)
pub fn scatter_segments(
    segs: &[(u64, usize)], src_len: usize, mut put: impl FnMut(u64, usize, usize) -> usize,
) -> usize {
    let mut at = 0usize;
    for &(va, n) in segs {
        let n = core::cmp::min(n, src_len - at);
        if n == 0 { break; }
        let done = put(va, at, n);
        at += done;
        if done < n { break; }
    }
    at
}

/// The ORDER the decisions above are asked in — the reaper's pass and the
/// wait loop it is driven from, both as drivers over a trait so they run with
/// no ring behind them.
#[path = "iopoll/seq.rs"] pub mod seq;

#[cfg(test)]
#[path = "iopoll/tests.rs"]
mod tests;
