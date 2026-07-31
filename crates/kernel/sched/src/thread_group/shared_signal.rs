// Linux `signal_struct::shared_pending` — the PROCESS-directed pending set.
//
// Linux keeps two pending sets per process: `task_struct::pending` (thread
// private, fed by `tgkill`/`tkill` and by synchronous faults) and
// `signal_struct::shared_pending` (process wide, fed by `kill(2)`,
// `sigqueue(3)`, `kill_pgrp`, a POSIX timer with `PIDTYPE_TGID`, …).
// `__send_signal_locked` chooses between them off the `enum pid_type` the
// sender passed (`kernel/signal.c`), and `dequeue_signal` drains the private
// queue first, then the shared one — so ANY thread reaching a delivery point
// with the signal unblocked can consume a process-directed signal.
//
// This kernel previously had no shared set: `sys_kill` resolved a tgid to the
// group LEADER and posted into that thread's private word, and the delivery
// path read only the running thread's own word. A process whose main thread
// blocks SIGTERM and leaves it to a worker — the shape of every glib/GIO
// program, and what systemd stops a service with — therefore ignored
// `kill(pid, SIGTERM)` forever. Proven against the host kernel by
// `userspace/wait_diff/groupsig.c`.
//
// The set lives HERE, on the thread group, because `ThreadGroup` IS this
// kernel's `signal_struct` (`pgid`, `sid`, `rlimits`, `posix_timers` and the
// `SIGNAL_GROUP_EXIT` latch already live on it). Putting it on the leader's
// `Task` — the previous convention, which `live::sigpend::group_signal_target`
// encoded — cannot be made correct: the leader's own word would then hold both
// its thread-directed and the process-directed signals, so a `tgkill` aimed at
// the leader while it blocks that signal would leak to a sibling.

use core::sync::atomic::Ordering;

use super::ThreadGroup;
use crate::task::SigInfo;

impl ThreadGroup {
    /// Linux `signal->shared_pending.signal` — the process-directed bitmap.
    /// # C: O(1)
    pub fn shared_pending(&self) -> u64 { self.shared_pending.load(Ordering::Acquire) }

    /// Linux `__send_signal_locked` with `type > PIDTYPE_PID`: reserve the
    /// bounded record queue, queue `info`, then publish the pending bit. The
    /// bit is set LAST so a consumer that observes it always finds the record.
    /// `false` from the record push is Linux's `sigqueue_alloc` returning NULL,
    /// which `live::send` turns into EAGAIN or a silent record loss.
    ///
    /// `info` is `None` for a sender that queues nothing (`kill(2)` from a
    /// context with no siginfo to carry); the bit alone is then the signal,
    /// exactly as Linux's bitmap-only path works.
    /// # C: O(1) amortized
    /// # Ctx: process — reserves queue capacity
    pub fn post_shared(&self, sig: u32, info: Option<SigInfo>) {
        let Some(bit) = crate::signum::bit_for(sig) else { return };
        if let Some(rec) = info { self.post_shared_record(rec); }
        self.shared_pending.fetch_or(bit, Ordering::Release);
    }

    /// Queue one record on the shared set WITHOUT publishing its pending bit —
    /// the record half of `post_shared`, so `live::send` can run the whole
    /// `__send_signal_locked` ladder (legacy-queue collapse, overflow reporting)
    /// between the two halves. The bit is published last so a consumer that
    /// observes it always finds the record.
    /// `false` = the bounded queue was full and the record was dropped.
    /// # C: O(1) amortized
    /// # Ctx: process — reserves queue capacity
    pub fn post_shared_record(&self, rec: SigInfo) -> bool {
        crate::sigqueue::queues_reserve(&self.shared_sigqueue, rec.signo);
        crate::sigqueue::queues_push(&self.shared_sigqueue, rec)
    }

    /// `post_shared_record` for a producer that may not allocate: the slot was
    /// reserved in process context (`reserve_shared`), so this only takes the
    /// queue lock and pushes. `false` = the bounded queue was full.
    /// # C: O(1)
    /// # Ctx: IRQ
    pub fn push_shared_prealloc(&self, rec: SigInfo) -> bool {
        crate::sigqueue::queues_push(&self.shared_sigqueue, rec)
    }

    /// Reserve the shared record slot for `signo` so an IRQ-context producer
    /// can publish without allocating — Linux `sigqueue_alloc` at
    /// `timer_create` time. # C: O(RT_QUEUE_CAP)
    /// # Ctx: process
    pub fn reserve_shared(&self, signo: u32) {
        crate::sigqueue::queues_reserve(&self.shared_sigqueue, signo)
    }

    /// Publish `sig`'s shared pending bit — the bitmap half of `post_shared`.
    /// # C: O(1)
    pub fn publish_shared(&self, sig: u32) {
        let Some(bit) = crate::signum::bit_for(sig) else { return };
        self.shared_pending.fetch_or(bit, Ordering::Release);
    }

    /// Linux `__dequeue_signal(&tsk->signal->shared_pending, …)`: claim `sig`
    /// for exactly ONE consumer. `None` means the bit was not set or a
    /// concurrent consumer won the claim; `Some(None)` is a claimed
    /// bitmap-only signal with no queued record.
    ///
    /// Same two-arm protocol the private set uses (`live::sigpend::claim_from`)
    /// — popping a record IS the claim, and for a bitmap-only signal the
    /// `fetch_and` is, so two threads racing one `kill(2)` can never both
    /// return it.
    /// # C: O(1)
    pub fn claim_shared(&self, sig: u32) -> Option<Option<SigInfo>> {
        let bit = crate::signum::bit_for(sig)?;
        if self.shared_pending.load(Ordering::Acquire) & bit == 0 { return None; }
        let (rec, empty) = crate::sigqueue::queues_pop(&self.shared_sigqueue, sig);
        if rec.is_some() {
            if empty { self.shared_pending.fetch_and(!bit, Ordering::Release); }
            return Some(rec);
        }
        if self.shared_pending.fetch_and(!bit, Ordering::AcqRel) & bit != 0 { Some(None) } else { None }
    }

    /// Linux `flush_sigqueue_mask` over the shared set: drop `mask`'s signals
    /// and their queued records. `sigaction(2)` installing an ignoring
    /// disposition discards what is already pending (POSIX 3.3.1.3), and
    /// `zap_other_threads`' caller has no use for them either.
    /// # C: O(|mask|)
    pub fn flush_shared_mask(&self, mask: u64) {
        let cleared = self.shared_pending.fetch_and(!mask, Ordering::AcqRel) & mask;
        let mut rest = cleared;
        while rest != 0 {
            let sig = rest.trailing_zeros() + 1;
            rest &= rest - 1;
            crate::sigqueue::queues_clear(&self.shared_sigqueue, sig);
        }
    }
}

/// Linux `wants_signal()`'s mask half: a thread can take `sig` unless it has
/// it blocked, and SIGKILL/SIGSTOP ignore the mask entirely.
///
/// Split out ungated so the rule is hosted-tested — `complete_signal` itself
/// needs the live registry and cannot be.
/// # C: O(1)
pub fn wants_signal(blocked: u64, bit: u64, unblockable: bool) -> bool {
    unblockable || (blocked & bit) == 0
}
