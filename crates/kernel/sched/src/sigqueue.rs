// Per-task signal-queue methods (queued `SigInfo` records + SIGCHLD
// child-exit events), split out of task.rs per `08§7` file-length cap. These
// are `impl Task` methods; the `sigqueue` / `child_sigq` fields + their init
// live in task.rs alongside the rest of the struct.
//
// Linux `struct sigpending` carries one `sigqueue` list for the whole set;
// this kernel keeps one bounded queue per signal number (`signum::sigq_index`)
// so a dequeue is O(1) without walking the list. Depth policy is Linux's:
// standard signals collapse to a single record (`legacy_queue` drops a second
// send while the first is still pending), real-time signals queue up to
// `RT_QUEUE_CAP` and deliver in arrival order.

use crate::signum;
use crate::task::{SigInfo, Task, RT_QUEUE_CAP};

/// `legacy_queue` depth for a standard (non-real-time) signal: Linux keeps at
/// most one queued record; a second send while the first is pending is
/// dropped, not queued.
const STD_QUEUE_CAP: usize = 1;

/// Queue depth for `signo` — `RT_QUEUE_CAP` for real-time signals,
/// `STD_QUEUE_CAP` for standard ones.
/// # C: O(1)
const fn queue_cap(signo: u32) -> usize {
    if signum::is_realtime(signo) { RT_QUEUE_CAP } else { STD_QUEUE_CAP }
}

impl Task {
    /// Reserve the complete bounded queue before an IRQ-context producer can
    /// publish this signal. # C: O(RT_QUEUE_CAP)
    /// # Ctx: process
    pub fn sigq_reserve(&self, signo: u32) {
        let Some(idx) = signum::sigq_index(signo) else { return };
        let mut queues = self.sigqueue.lock();
        let additional = queue_cap(signo).saturating_sub(queues[idx].len());
        queues[idx].reserve(additional);
    }

    /// Enqueue `info` on the per-task queue for `info.signo`. Returns true if
    /// accepted, false if dropped by the per-signal cap (Linux drops silently
    /// and still sets the pending bit). Caller is also responsible for setting
    /// the pending bit on `sigpending`. SIGCHLD MUST use `child_sigq_push` —
    /// it has no slot here.
    /// # C: O(1)
    pub fn sigq_push(&self, info: SigInfo) -> bool {
        let Some(idx) = signum::sigq_index(info.signo) else { return false };
        let mut g = self.sigqueue.lock();
        if g[idx].len() >= queue_cap(info.signo) { return false; }
        debug_assert!(g[idx].len() < g[idx].capacity(),
            "IRQ signal producer must reserve queue capacity in process context");
        g[idx].push_back(info);
        true
    }

    /// Pop the longest-waiting siginfo for `signo`. Returns `None` when the
    /// queue is empty (the bitmap bit was set by a source that queues nothing
    /// — `kill(2)` — and the caller synthesises an `SI_USER` siginfo). The
    /// bool reports whether the queue is empty AFTER the pop: POSIX clears a
    /// real-time signal's pending bit only when its queue drains.
    /// # C: O(1)
    pub fn sigq_pop(&self, signo: u32) -> (Option<SigInfo>, bool) {
        let Some(idx) = signum::sigq_index(signo) else { return (None, true) };
        let mut g = self.sigqueue.lock();
        let info = g[idx].pop_front();
        let empty = g[idx].is_empty();
        (info, empty)
    }

    /// B117: enqueue a SIGCHLD child-exit `info` (pid=child VPID,
    /// code=CLD_*, value=exit status). Caller sets the pending bit.
    /// Capped at `RT_QUEUE_CAP`; drop oldest on overflow. Pop is the
    /// inverse (`child_sigq.lock().pop_front()` at the delivery site).
    /// # C: O(1)
    pub fn child_sigq_push(&self, info: SigInfo) {
        let mut g = self.child_sigq.lock();
        if g.len() >= RT_QUEUE_CAP { g.pop_front(); }
        g.push_back(info);
    }

    /// Pop the oldest queued SIGCHLD child-exit siginfo (pid=child VPID,
    /// code=CLD_*, value=wait-encoded status). Returns the record (`None`
    /// if none queued → caller synthesises signo-only) plus whether the
    /// queue is empty after the pop, so SIGCHLD's collapsed pending bit
    /// clears only when the last child event drains — the inverse of
    /// `child_sigq_push`, mirroring `sigq_pop`. Used by signalfd read and
    /// SA_SIGINFO SIGCHLD delivery. # C: O(1)
    pub fn child_sigq_pop(&self) -> (Option<SigInfo>, bool) {
        let mut g = self.child_sigq.lock();
        let info = g.pop_front();
        let empty = g.is_empty();
        (info, empty)
    }

    /// Dequeue one signal's queued record and report whether its pending bit
    /// must stay set. Single owner of the "which queue does this signal use"
    /// decision, so delivery (`take_lowest_pending`), `rt_sigtimedwait` and
    /// `signalfd` can never disagree about it.
    /// # C: O(1)
    pub fn dequeue_siginfo(&self, signo: u32) -> (Option<SigInfo>, bool) {
        if signo == crate::signum::Signum::Sigchld as u32 { self.child_sigq_pop() }
        else if signum::is_realtime(signo) { self.sigq_pop(signo) }
        else { (self.sigq_pop(signo).0, true) }
    }
}
