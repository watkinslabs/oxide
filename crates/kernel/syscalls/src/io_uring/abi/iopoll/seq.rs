// The SEQUENCING of a polled ring: what the reaper does, in what order, and
// the loop `io_uring_enter(IORING_ENTER_GETEVENTS)` drives it from.
//
// The individual decisions live beside this ([`super::reap_step`],
// [`super::before_poll`], [`super::after_poll`], [`super::precheck`],
// [`super::completed_res`]) and each of them is checkable on its own. The
// ORDER they are asked in is a separate thing to be wrong about, and it is
// where a polled ring's three failure modes live: a request completed twice, a
// completion posted against a request somebody else already owns, and a
// transfer nothing ever reaps.
//
// Three orderings this states, each of which is a defect if reversed:
//
//   * CLAIM LAST. A pass asks whether the backend has finished BEFORE it asks
//     to own the request. Claiming first would take a request whose result is
//     not in yet, and the transfer's result would then be dropped by the pass
//     that owned it.
//   * RELEASE BEFORE POST. The request leaves the polled set — and its queued
//     transfer is cleared — before its completion is posted. A pass that
//     posted first leaves a window in which another pass finds the request
//     still queued and its backend still marked finished.
//   * REAP AFTER POLL. The loop drives the backends and only then turns what
//     they finished into completions. Reaping first would report the previous
//     pass's work as this pass's and spin one pass longer than it needed to.
//
// Both drivers take their environment as a trait, so they run without a ring,
// a backend, an address space or a scheduler — which is the point: the live
// halves of both are target-gated and therefore unreachable from a test.

use syscall::errno::Errno;

use super::{after_poll, before_poll, completed_res, precheck, reap_step, ReapStep, Step};

// --- the reaper ---------------------------------------------------------

/// What the backend left in a finished transfer's result slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Taken {
    /// The transfer was marked finished and its slot was empty. Nothing can
    /// say what happened to the bytes, so it is an I/O error rather than a
    /// zero-length transfer, which would read as end-of-file.
    Lost,
    /// The backend refused or failed it; the value is the negative errno the
    /// completion carries.
    Failed(i64),
    /// The backend moved this many bytes.
    Bytes(usize),
}

/// One ring's polled set, as a reap pass sees it.
pub trait ReapSet {
    /// One request, however the caller names it.
    type Req;

    /// Every transfer this ring's backends still owe a result for.
    /// # C: O(N_queued)
    fn queued(&mut self) -> alloc::vec::Vec<Self::Req>;
    /// The request still carries a queued transfer. # C: O(1)
    fn has_queued(&mut self, r: &Self::Req) -> bool;
    /// Its backend has published a result. # C: O(1)
    fn backend_done(&mut self, r: &Self::Req) -> bool;
    /// Take ownership of it — the one compare-exchange a cancellation and a
    /// deadline go through too. # C: O(1)
    fn claim(&mut self, r: &Self::Req) -> bool;
    /// The transfer moves bytes OUT of the caller's buffer. # C: O(1)
    fn is_write(&mut self, r: &Self::Req) -> bool;
    /// Empty the result slot. # C: O(1)
    fn take(&mut self, r: &Self::Req) -> Taken;
    /// Put a completed read's bytes in the SUBMITTER's memory, reporting how
    /// many landed. # C: O(n)
    fn scatter(&mut self, r: &Self::Req, delivered: usize) -> usize;
    /// Clear the queued transfer and drop the request from the polled set.
    /// # C: O(N_queued)
    fn release(&mut self, r: &Self::Req);
    /// Post its completion. # C: O(1)
    fn post(&mut self, r: &Self::Req, res: i64);
}

/// One pass over a ring's polled set, reporting how many completions it
/// posted. The reference's `io_do_iopoll` second pass.
/// # C: O(N_queued)
pub fn reap_pass<S: ReapSet>(s: &mut S) -> usize {
    let mut posted = 0usize;
    for r in s.queued() {
        let has = s.has_queued(&r);
        // Short-circuited deliberately rather than evaluated up front: neither
        // question may be ASKED once an earlier one has answered no, and the
        // claim least of all — it is not a query but a transfer of ownership.
        let done = has && s.backend_done(&r);
        let claimed = done && s.claim(&r);
        if reap_step(has, done, claimed) != ReapStep::Take { continue; }
        let write = s.is_write(&r);
        let res = match s.take(&r) {
            Taken::Lost => -(Errno::Eio.as_i32() as i64),
            Taken::Failed(e) => e,
            Taken::Bytes(n) => {
                let landed = if write { n } else { s.scatter(&r, n) };
                completed_res(write, n, landed)
            }
        };
        s.release(&r);
        s.post(&r, res);
        posted += 1;
    }
    posted
}

// --- the wait loop ------------------------------------------------------

/// The ring an `IORING_ENTER_GETEVENTS` wait on a polled ring drives.
pub trait PollWait {
    /// Completions the caller asked for, already clamped to the CQ depth.
    /// # C: O(1)
    fn min_events(&self) -> u32;
    /// Move whatever is in the overflow backlog into the CQ ring.
    /// # C: O(N_backlog)
    fn flush_overflow(&mut self);
    /// This ring lost a completion. # C: O(1)
    fn dropped(&self) -> bool;
    /// Report the lost completion once and forget it. # C: O(1)
    fn clear_dropped(&mut self) -> bool;
    /// Completions userspace has not consumed. # C: O(1)
    fn cq_ready(&mut self) -> u32;
    /// How many distinct backends have outstanding polled I/O. Zero ends the
    /// loop: there is nothing a poll could find. # C: O(N_queued)
    fn targets(&mut self) -> u32;
    /// Sleep for part of the next transfer's expected service time, reporting
    /// how long it slept and when that transfer was issued. # C: O(1)
    fn hybrid_sleep(&mut self) -> Option<(u64, u64)>;
    /// Drive every outstanding backend once. # C: O(N_targets)
    fn poll_targets(&mut self, oneshot: bool);
    /// Turn what the backends finished into completions. # C: O(N_queued)
    fn reap(&mut self) -> usize;
    /// Fold this pass's observed service time into the ring's estimate.
    /// # C: O(1)
    fn hybrid_observe(&mut self, slept: u64, issued_at: u64);
    /// Let whatever the poll made runnable actually run. # C: O(1)
    fn yield_cpu(&mut self);
    /// A signal is pending for the spinning caller. # C: O(1)
    fn signal_pending(&mut self) -> bool;
    /// The processor is needed elsewhere. # C: O(1)
    fn need_resched(&mut self) -> bool;
}

/// The `IORING_ENTER_GETEVENTS` wait for a polled ring: `0`, `-EINTR`, or
/// `-EBADR`. The reference's `io_iopoll_check`.
///
/// May return success having reaped FEWER completions than asked for, which is
/// the contract and not a shortfall — see [`super::before_poll`].
/// # C: O(spin until min_complete or a break condition)
pub fn poll_wait<W: PollWait>(w: &mut W) -> i64 {
    let min = w.min_events();
    w.flush_overflow();

    if let Some(r) = precheck(w.dropped(), w.cq_ready()) {
        return match r {
            Ok(()) => 0,
            Err(e) => { w.clear_dropped(); -(e.as_i32() as i64) }
        };
    }

    loop {
        let targets = w.targets();
        match before_poll(targets, min, targets > 1) {
            Step::Stop => break,
            Step::Interrupted => return -(Errno::Eintr.as_i32() as i64),
            Step::Poll { oneshot } => {
                let timed = w.hybrid_sleep();
                w.poll_targets(oneshot);
                // The backends have run their completions; this is what turns
                // one into a CQE, and nothing else looks at it.
                w.reap();
                if let Some((slept, issued_at)) = timed { w.hybrid_observe(slept, issued_at); }
                w.flush_overflow();
                w.yield_cpu();
                let sig = w.signal_pending();
                let resched = w.need_resched();
                let events = w.cq_ready();
                match after_poll(events, min, sig, resched) {
                    Step::Interrupted => return -(Errno::Eintr.as_i32() as i64),
                    Step::Stop => break,
                    Step::Poll { .. } => continue,
                }
            }
        }
    }

    w.flush_overflow();
    if w.clear_dropped() { return -(Errno::Ebadr.as_i32() as i64); }
    0
}

#[cfg(test)]
#[path = "seq_tests.rs"]
mod tests;
