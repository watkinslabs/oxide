// Per-task signal-queue methods (queued `SigInfo` records), split out of
// task.rs per `08§7` file-length cap. These are `impl Task` methods; the
// `sigqueue` field + its init live in task.rs alongside the rest of the struct.
//
// Linux `struct sigpending` carries one `sigqueue` list for the whole set;
// this kernel keeps one queue per signal number (`signum::sigq_index`) so a
// dequeue is O(1) without walking the list. Depth policy is Linux's: standard
// signals collapse to a single record (`legacy_queue` drops a second send while
// the first is still pending), real-time signals queue in arrival order and are
// bounded by `RLIMIT_SIGPENDING` — the per-user count of queued records, not a
// per-signal or per-task constant.
//
// The charge travels ON the record (Linux `struct sigqueue::ucounts`), which is
// what makes the accounting symmetric by construction: `Queued` releases its
// unit in `Drop`, so a dequeue, a flush, a thread-group teardown and a task exit
// that drops the whole array all settle the account without any of them needing
// to know it exists.

use alloc::collections::VecDeque;
use sync::{Spinlock, TaskList as TaskListClass};
use ucounts::{Counter, UcountKey};

use crate::signum;
use crate::task::{SigInfo, Task, RT_QUEUE_CAP};

/// One per-signal record slot for every signo — Linux's `struct
/// sigpending::list`, indexed by `signum::sigq_index` so a dequeue is O(1)
/// without walking a list.
pub const SIGQ_SLOTS: usize = 64;

/// How a record's `RLIMIT_SIGPENDING` slot is paid for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Charge {
    /// A process-context send: charge `key`'s account and refuse the record if
    /// the post-charge count is over `limit`, unless `override_rlimit` (Linux
    /// `sig_get_ucounts`, whose `override_rlimit` argument is
    /// `sigsend::override_rlimit`).
    Account { key: UcountKey, limit: u64, override_rlimit: bool },
    /// Linux `SIGQUEUE_PREALLOC`: the slot was reserved and accounted in
    /// process context, so publishing it charges nothing and freeing it
    /// releases nothing here. This is the only form a hard-IRQ producer may
    /// use — the account table is a plain `TaskList` spinlock that process
    /// context holds with IRQs enabled (`06§3.1`), so an IRQ-context charge
    /// would be a deadlock, exactly as Linux's expiry path never allocates.
    Prealloc,
}

/// One queued record and the account holding its slot — Linux `struct sigqueue`
/// with its `ucounts` back-pointer.
///
/// NOT `Copy`/`Clone` on purpose: duplicating a record would duplicate a charge
/// that only one `Drop` would ever release.
pub struct Queued {
    info: SigInfo,
    /// `None` is `SIGQUEUE_PREALLOC` — nothing to release.
    charge: Option<UcountKey>,
}

impl Queued {
    /// The record's payload. # C: O(1)
    pub fn info(&self) -> SigInfo { self.info }
}

impl Drop for Queued {
    /// Linux `__sigqueue_free`: `if (q->ucounts) dec_rlimit_put_ucounts(...)`.
    /// Every removal path — dequeue, `flush_sigqueue_mask`, thread-group
    /// teardown, task exit dropping the whole array — runs this exactly once.
    /// # C: O(chain * log N); # Lk: TaskList
    fn drop(&mut self) {
        if let Some(key) = self.charge { ucounts::dec_rlimit(key, Counter::Sigpending, 1); }
    }
}

/// `ThreadGroup`'s copy of that array, behind a `Box` because `ThreadGroup` is
/// built BY VALUE inside `Task::new_with_mm` before it is moved into its `Arc`:
/// an inline `[VecDeque<Queued>; 64]` is 2 KiB of stack in a frame that was
/// already 4.2 KiB on a 16 KiB guard-paged kstack, and the clone path overflowed
/// into the guard page (`#DF`, caught by the boot gate). `vec![…]` builds on the
/// heap directly, so no stack temporary is ever materialised.
pub type SigQueues = Spinlock<alloc::boxed::Box<[VecDeque<Queued>]>, TaskListClass>;

/// Heap-build an empty record array. # C: O(SIGQ_SLOTS)
pub fn new_queues() -> SigQueues {
    Spinlock::new((0..SIGQ_SLOTS).map(|_| VecDeque::new())
        .collect::<alloc::vec::Vec<_>>().into_boxed_slice())
}

/// Reserve the real-time queue depth an IRQ-context producer may publish into
/// without allocating — Linux allocates a POSIX timer's record once at
/// `timer_create` for the same reason. # C: O(RT_QUEUE_CAP)
/// # Ctx: process
pub fn queues_reserve<A: AsMut<[VecDeque<Queued>]>>(q: &Spinlock<A, TaskListClass>, signo: u32) {
    let Some(idx) = signum::sigq_index(signo) else { return };
    let mut g = q.lock();
    let queues = g.as_mut();
    let additional = prealloc_depth(signo).saturating_sub(queues[idx].len());
    queues[idx].reserve(additional);
}

/// Enqueue `info`. `false` = the record was refused — by `legacy_queue`'s
/// single-record rule for a standard signal, by `RLIMIT_SIGPENDING` for a
/// charged real-time one, or by the absence of a reserved slot for an IRQ
/// producer. Linux's caller then either fails the send with EAGAIN or accepts
/// the "silent loss of information" (`sigsend::overflow_is_eagain`).
///
/// The charge is taken UNDER the queue lock and released again on refusal, so
/// the account and the queue cannot desync even under a concurrent send.
/// # C: O(chain * log N) charged, O(1) prealloc
pub fn queues_push<A: AsMut<[VecDeque<Queued>]>>(
    q: &Spinlock<A, TaskListClass>, info: SigInfo, charge: Charge) -> bool
{
    let Some(idx) = signum::sigq_index(info.signo) else { return false };
    let mut gg = q.lock();
    let g = gg.as_mut();
    if !structurally_admits(&g[idx], info.signo, charge) { return false; }
    let held = match charge {
        Charge::Prealloc => None,
        // A standard signal's record is not charged here — see
        // [`charges_account`]. `legacy_queue` already caps it at one record per
        // signal per set, so the limit has nothing to bound.
        Charge::Account { .. } if !charges_account(info.signo) => None,
        Charge::Account { key, limit, override_rlimit } => {
            let charged = ucounts::inc_rlimit(key, Counter::Sigpending, 1).max(0) as u64;
            if !crate::rlimit::pending::admits(charged, limit, override_rlimit) {
                ucounts::dec_rlimit(key, Counter::Sigpending, 1);
                return false;
            }
            Some(key)
        }
    };
    g[idx].push_back(Queued { info, charge: held });
    true
}

/// Whether a queued record for `signo` holds an `RLIMIT_SIGPENDING` slot.
///
/// REAL-TIME SIGNALS ONLY, and the restriction is load-bearing rather than a
/// simplification. Releasing a slot means adjusting the per-user account, whose
/// table is a plain `TaskList` spinlock that process context holds with IRQs
/// enabled (`06§3.1`); a hard-IRQ producer that freed a charged record would
/// deadlock against it. `prepare_signal`'s flush — the one record-freeing path
/// a hard IRQ reaches (`live::send::send_signal_irq` -> `flush_local`) — drops
/// only `SIG_KERNEL_STOP_MASK` and `SIGCONT`, every one of them a STANDARD
/// signal. Charging standard signals nowhere therefore makes that path
/// provably charge-free instead of merely unlikely to bite.
///
/// What it costs: Linux also charges a standard signal queued with a negative
/// `si_code` (`sigqueue(2)`, `SI_TIMER`, `SI_TKILL`). `legacy_queue` caps those
/// at ONE record per signal per pending set, so at most 32 private + 32 shared
/// records per process go uncounted — a bounded, non-exhaustible shortfall,
/// against an unbounded real-time queue which is what the limit exists to stop.
/// Removing the restriction needs the account table to become an arena of
/// never-freed atomic counters, the way Linux's `q->ucounts->rlimit[type]` is;
/// that is a `ucounts` redesign, not a signal-path change.
/// # C: O(1)
pub const fn charges_account(signo: u32) -> bool { signum::is_realtime(signo) }

/// The structural half of admission, before any account is touched: a standard
/// signal keeps at most one record, and an IRQ producer may use only a slot
/// that process context already reserved.
/// # C: O(1)
fn structurally_admits(queue: &VecDeque<Queued>, signo: u32, charge: Charge) -> bool {
    if !signum::is_realtime(signo) { return queue.len() < STD_QUEUE_CAP; }
    match charge {
        // `RLIMIT_SIGPENDING` is the only bound Linux puts on a real-time
        // queue; a per-signal constant here would refuse records the limit
        // admits and make the limit unobservable.
        Charge::Account { .. } => true,
        Charge::Prealloc => queue.len() < queue.capacity(),
    }
}

/// Pop the longest-waiting record for `signo`; the bool is "queue empty AFTER
/// the pop", which is what keeps a real-time signal's pending bit set while
/// records remain. The popped `Queued` is dropped here, which is what releases
/// its `RLIMIT_SIGPENDING` slot. # C: O(1)
pub fn queues_pop<A: AsMut<[VecDeque<Queued>]>>(q: &Spinlock<A, TaskListClass>, signo: u32) -> (Option<SigInfo>, bool) {
    let Some(idx) = signum::sigq_index(signo) else { return (None, true) };
    let mut gg = q.lock();
    let g = gg.as_mut();
    let info = g[idx].pop_front().map(|rec| rec.info());
    let empty = g[idx].is_empty();
    (info, empty)
}

/// Every queued record, WITHOUT consuming any of them, lowest signal number
/// first and in arrival order within each signal. This is the view
/// `PTRACE_PEEKSIGINFO` walks: Linux iterates `sigpending::list`, which is one
/// list in arrival order; this kernel keeps a queue per signal, so the stable
/// enumeration order it can offer is by signal number.
/// # C: O(SIGQ_SLOTS + queued)
pub fn queues_snapshot<A: AsMut<[VecDeque<Queued>]>>(q: &Spinlock<A, TaskListClass>)
    -> alloc::vec::Vec<SigInfo>
{
    let mut out = alloc::vec::Vec::new();
    let mut gg = q.lock();
    for queue in gg.as_mut().iter() { out.extend(queue.iter().map(Queued::info)); }
    out
}

/// Linux `flush_sigqueue_mask` for one signal: discard every queued record.
/// Dropping them here is what releases their slots.
/// # C: O(queued)
pub fn queues_clear<A: AsMut<[VecDeque<Queued>]>>(q: &Spinlock<A, TaskListClass>, signo: u32) {
    let Some(idx) = signum::sigq_index(signo) else { return };
    q.lock().as_mut()[idx].clear();
}

/// Records currently queued for `signo`. # C: O(1)
pub fn queues_len<A: AsMut<[VecDeque<Queued>]>>(q: &Spinlock<A, TaskListClass>, signo: u32) -> usize {
    let Some(idx) = signum::sigq_index(signo) else { return 0 };
    q.lock().as_mut()[idx].len()
}

/// `legacy_queue` depth for a standard (non-real-time) signal: Linux keeps at
/// most one queued record; a second send while the first is pending is
/// dropped, not queued.
const STD_QUEUE_CAP: usize = 1;

/// Real-time slots a process-context reservation guarantees, so a hard-IRQ
/// producer (a POSIX timer expiry) always has somewhere to publish without
/// allocating — this kernel's stand-in for Linux's `SIGQUEUE_PREALLOC` record.
/// It is a RESERVATION FLOOR, not the queue's limit: `RLIMIT_SIGPENDING` bounds
/// how many charged records a process-context sender may add above it.
/// # C: O(1)
const fn prealloc_depth(signo: u32) -> usize {
    if signum::is_realtime(signo) { RT_QUEUE_CAP } else { STD_QUEUE_CAP }
}

impl Task {
    /// Reserve the complete bounded queue before an IRQ-context producer can
    /// publish this signal. # C: O(RT_QUEUE_CAP)
    /// # Ctx: process
    pub fn sigq_reserve(&self, signo: u32) { queues_reserve(&self.sigqueue, signo) }

    /// The `RLIMIT_SIGPENDING` charge a process-context send to THIS task
    /// takes: Linux charges `task_ucounts(t)` — the TARGET's account, not the
    /// sender's — and compares the post-charge count against the target's own
    /// limit. `override_rlimit` is `sigsend::override_rlimit`, the one owner of
    /// that predicate.
    /// # C: O(1); # Lk: TaskList (rlimit table, momentary)
    pub fn sigq_charge(&self, override_rlimit: bool) -> Charge {
        Charge::Account {
            key: crate::ucounts::charged_key(self),
            limit: self.rlimit(crate::rlimit::rlim::SIGPENDING).0,
            override_rlimit,
        }
    }

    /// Enqueue `info` on the per-task queue for `info.signo`. Returns true if
    /// accepted, false if refused by `legacy_queue`'s single-record rule or by
    /// `RLIMIT_SIGPENDING` (Linux then either fails the send with EAGAIN or
    /// accepts the silent loss of the record). Caller is also responsible for
    /// setting the pending bit on `sigpending`.
    /// # C: O(1)
    pub fn sigq_push(&self, info: SigInfo, charge: Charge) -> bool {
        queues_push(&self.sigqueue, info, charge)
    }

    /// Records this thread currently holds queued for `signo`. # C: O(1)
    pub fn sigq_len(&self, signo: u32) -> usize { queues_len(&self.sigqueue, signo) }

    /// Pop the longest-waiting siginfo for `signo`. Returns `None` when the
    /// queue is empty (the bitmap bit was set by a source that queues nothing
    /// — `kill(2)` — and the caller synthesises an `SI_USER` siginfo). The
    /// bool reports whether the queue is empty AFTER the pop: POSIX clears a
    /// real-time signal's pending bit only when its queue drains.
    /// # C: O(1)
    pub fn sigq_pop(&self, signo: u32) -> (Option<SigInfo>, bool) { queues_pop(&self.sigqueue, signo) }

    /// Non-destructive view of this thread's queued records, for
    /// `PTRACE_PEEKSIGINFO` — which must not consume what it reports.
    /// # C: O(SIGQ_SLOTS + queued)
    pub fn sigq_snapshot(&self) -> alloc::vec::Vec<SigInfo> { queues_snapshot(&self.sigqueue) }

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
        let mut claimed = self.claim_pending(sig)?;
        // Linux `dequeue_signal` -> `posixtimer_rearm(&ksig->info)`: a POSIX
        // timer's record is completed at the moment it is taken, not when it is
        // queued, because `si_overrun` counts the expirations missed while it
        // sat pending. Runs with no queue lock held — the record is already
        // popped — so the timer lock never enters the dequeue's lock order.
        if let Some(rec) = claimed.as_mut() { self.rearm_timer_record(rec); }
        Some(claimed)
    }

    /// [`crate::timers::posixtimer_rearm`], where the POSIX timer table exists.
    /// # C: O(1)
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    fn rearm_timer_record(&self, rec: &mut SigInfo) { crate::timers::posixtimer_rearm(self, rec) }

    /// Builds without the timer table (`sched` as a plain dependency) have no
    /// POSIX timer to rearm, so a queued record is handed over unchanged.
    /// # C: O(1)
    #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
    fn rearm_timer_record(&self, _rec: &mut SigInfo) {}

    /// The claim protocol itself: private set first, then the process-wide
    /// shared one. Split from [`Task::dequeue_pending`] so the `posixtimer_rearm`
    /// stamp runs strictly after both queue locks are released.
    /// # C: O(1)
    fn claim_pending(&self, sig: u32) -> Option<Option<SigInfo>> {
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
        if signum::is_realtime(signo) { self.sigq_pop(signo) }
        else { (self.sigq_pop(signo).0, true) }
    }
}
