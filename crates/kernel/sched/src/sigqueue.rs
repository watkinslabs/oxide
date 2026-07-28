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

use alloc::collections::VecDeque;
use sync::{Spinlock, TaskList as TaskListClass};

use crate::signum;
use crate::task::{SigInfo, Task, RT_QUEUE_CAP};

/// The per-signal record array both pending sets are built from — Linux's
/// `struct sigpending::list`, once. `Task` owns one for the thread-private set
/// and `ThreadGroup` owns one for `signal_struct::shared_pending`, so the
/// "which queue does this signal use, and how deep is it" decision has ONE
/// implementation and the two sets cannot drift apart.
pub type SigQueues = Spinlock<[VecDeque<SigInfo>; 64], TaskListClass>;

/// Reserve the complete bounded queue for `signo` so an IRQ-context producer
/// can publish without allocating. # C: O(RT_QUEUE_CAP)
/// # Ctx: process
pub fn queues_reserve(q: &SigQueues, signo: u32) {
    let Some(idx) = signum::sigq_index(signo) else { return };
    let mut queues = q.lock();
    let additional = queue_cap(signo).saturating_sub(queues[idx].len());
    queues[idx].reserve(additional);
}

/// Enqueue `info`, honouring the per-signal depth cap. `false` = dropped by
/// the cap (Linux drops silently and still sets the pending bit).
/// # C: O(1)
pub fn queues_push(q: &SigQueues, info: SigInfo) -> bool {
    let Some(idx) = signum::sigq_index(info.signo) else { return false };
    let mut g = q.lock();
    if g[idx].len() >= queue_cap(info.signo) { return false; }
    debug_assert!(g[idx].len() < g[idx].capacity(),
        "IRQ signal producer must reserve queue capacity in process context");
    g[idx].push_back(info);
    true
}

/// Pop the longest-waiting record for `signo`; the bool is "queue empty AFTER
/// the pop", which is what keeps a real-time signal's pending bit set while
/// records remain. # C: O(1)
pub fn queues_pop(q: &SigQueues, signo: u32) -> (Option<SigInfo>, bool) {
    let Some(idx) = signum::sigq_index(signo) else { return (None, true) };
    let mut g = q.lock();
    let info = g[idx].pop_front();
    let empty = g[idx].is_empty();
    (info, empty)
}

/// Linux `flush_sigqueue_mask` for one signal: discard every queued record.
/// # C: O(queued)
pub fn queues_clear(q: &SigQueues, signo: u32) {
    let Some(idx) = signum::sigq_index(signo) else { return };
    q.lock()[idx].clear();
}

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
    pub fn sigq_reserve(&self, signo: u32) { queues_reserve(&self.sigqueue, signo) }

    /// Enqueue `info` on the per-task queue for `info.signo`. Returns true if
    /// accepted, false if dropped by the per-signal cap (Linux drops silently
    /// and still sets the pending bit). Caller is also responsible for setting
    /// the pending bit on `sigpending`. SIGCHLD MUST use `child_sigq_push` —
    /// it has no slot here.
    /// # C: O(1)
    pub fn sigq_push(&self, info: SigInfo) -> bool { queues_push(&self.sigqueue, info) }

    /// Pop the longest-waiting siginfo for `signo`. Returns `None` when the
    /// queue is empty (the bitmap bit was set by a source that queues nothing
    /// — `kill(2)` — and the caller synthesises an `SI_USER` siginfo). The
    /// bool reports whether the queue is empty AFTER the pop: POSIX clears a
    /// real-time signal's pending bit only when its queue drains.
    /// # C: O(1)
    pub fn sigq_pop(&self, signo: u32) -> (Option<SigInfo>, bool) { queues_pop(&self.sigqueue, signo) }

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

    /// Linux `dequeue_signal`: consume `sig` for this thread, trying the
    /// thread-private set first and then the process-wide `shared_pending`,
    /// exactly as `__dequeue_signal(&tsk->pending, …)` then
    /// `&tsk->signal->shared_pending`. `None` = neither set held it, or a
    /// concurrent consumer won the claim (Linux's `get_signal` seeing
    /// `dequeue_signal` return 0). `Some(None)` = a claimed bitmap-only signal.
    ///
    /// Lives on `Task` rather than in `live::sigpend` because `signalfd` and
    /// `rt_sigtimedwait` reach it from crates that build without the
    /// kernel-only `live` module — one owner for the claim protocol, no second
    /// copy that could disagree about which set was consumed.
    /// # C: O(1)
    pub fn dequeue_pending(&self, sig: u32) -> Option<Option<SigInfo>> {
        let bit = signum::bit_for(sig)?;
        if self.sigpending.load(core::sync::atomic::Ordering::Acquire) & bit != 0 {
            let (rec, empty) = self.dequeue_siginfo(sig);
            if rec.is_some() {
                // Popping a record IS the claim — no other consumer can pop it.
                if empty { self.sigpending.fetch_and(!bit, core::sync::atomic::Ordering::Release); }
                return Some(rec);
            }
            // Bitmap-only: the bit is the token, and exactly one clearer
            // observes it set in the prior value.
            if self.sigpending.fetch_and(!bit, core::sync::atomic::Ordering::AcqRel) & bit != 0 {
                return Some(None);
            }
        }
        self.thread_group.claim_shared(sig)
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
