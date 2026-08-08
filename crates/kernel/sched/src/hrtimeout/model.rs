// Linux hrtimer range model for timed waits. Pure decision logic — no `Task`,
// no lock, no clock — so every rule below is exercised by `cargo test` rather
// than only by a boot (`hrtimeout/tests.rs`).
//
// Two times per armed wait, set by Linux's `hrtimer_set_expires_range_ns`:
//
//   soft (`_softexpires`) — the caller's own deadline. A wait may not end
//                           before it: "the absolute earliest expiry time".
//   hard (`node.expires`) — `soft + slack`; the latest instant Linux permits:
//                           "Is setup by adding slack to the `_softexpires`
//                           value".
//
// The queue is ordered by HARD (Linux's rbtree key) and the hardware one-shot
// is armed from the head's hard time, while `__hrtimer_run_queues`
// fires everything whose SOFT time has passed:
//
//     if (basenow < hrtimer_get_softexpires(timer))
//             break;
//
// Programming LATE and firing EARLY is the entire coalescing trick: N waits
// whose `[soft, hard]` ranges overlap cost ONE interrupt, not N. Without it a
// desktop's thousands of short timed waits would each buy their own timer
// interrupt.

use alloc::vec::Vec;

/// Linux `NSEC_PER_MSEC`.
const NSEC_PER_MSEC: u64 = 1_000_000;

/// Linux `MAX_SLACK` — the ceiling `select_estimate_accuracy`
/// puts on poll/select/epoll coalescing.
pub const MAX_SLACK_NS: u64 = 100 * NSEC_PER_MSEC;

/// Linux `divfactor` — poll/select/epoll spend 0.1% of the
/// remaining timeout as slack.
const SLACK_DIVISOR: u64 = 1000;

/// Linux `divfactor = divfactor / 5` — a `nice > 0` task
/// spends 0.5% instead, because its wakeups matter less.
const SLACK_DIVISOR_NICE: u64 = SLACK_DIVISOR / 5;

/// `ktime_add_safe`: the hard expiry saturates rather
/// than wrapping, so a `KTIME_MAX`-clamped absolute deadline plus slack cannot
/// alias to a near-term one.
/// # C: O(1)
pub fn hard_expiry(soft_ns: u64, slack_ns: u64) -> u64 { soft_ns.saturating_add(slack_ns) }

/// Linux `select_estimate_accuracy` — the slack
/// poll/select/epoll_wait grant a timeout. Zero task slack (an RT/deadline
/// task) means exact, floor at the task's own slack, cap at `MAX_SLACK_NS`.
/// `remaining_ns` is `deadline - now`, Linux's `timespec64_sub(*tv, now)`.
/// # C: O(1)
pub fn estimate_accuracy(remaining_ns: u64, task_slack_ns: u64, nice_positive: bool) -> u64 {
    if task_slack_ns == 0 { return 0; }
    let divisor = if nice_positive { SLACK_DIVISOR_NICE } else { SLACK_DIVISOR };
    // `__estimate_accuracy` splits this across tv_sec/tv_nsec only because it
    // works on a timespec; both divisors divide NSEC_PER_SEC exactly, so the
    // split is arithmetically identical to one division of the ns count.
    let estimate = (remaining_ns / divisor).min(MAX_SLACK_NS);
    if estimate < task_slack_ns { task_slack_ns } else { estimate }
}

/// Fold the earliest armed wait expiry into an already-resolved next-interrupt
/// deadline. Linux `__hrtimer_get_next_event` takes the
/// min over active bases; `hrtimer_reprogram` then only
/// touches the device when the candidate is strictly earlier than what is
/// already programmed — which `min` expresses.
///
/// A wait whose hard expiry is already in the PAST is deliberately dropped
/// instead of programmed: Linux's own reason is that
/// arming for an expired timer re-arms at minimal delta and "Lather, rinse and
/// repeat". The interrupt that services it is already on its way — the caller's
/// `base_ns` is bounded by the accounting tick.
/// # C: O(1)
pub fn fold_wait_expiry(now_ns: u64, base_ns: u64, wait_hard_ns: u64) -> u64 {
    if wait_hard_ns > now_ns { base_ns.min(wait_hard_ns) } else { base_ns }
}

/// One armed wait. `payload` is the wake handle — a `Weak<Task>` in the kernel,
/// a plain id in tests.
pub struct Armed<P> {
    pub soft_ns: u64,
    pub hard_ns: u64,
    pub tid: u32,
    pub payload: P,
}

/// Deadline-ordered set of armed waits — Linux's per-CPU
/// `timerqueue_linked_head`, whose
/// sort key is the HARD expiry and whose leftmost entry is cached for O(1)
/// "what is the next event".
///
/// Stored DESCENDING so the earliest hard expiry is the LAST element: that
/// makes both hot operations — read the next event, take the next expiry —
/// O(1) tail accesses on a `Vec`, where a leftmost-first layout would memmove
/// the whole tail on every pop. Insertion is O(N) memmove against the ~one
/// entry per timed-waiting task, replacing an O(N_all_tasks) registry walk that
/// took the registry lock and cloned an `Arc` per task.
pub struct DeadlineQueue<P> {
    armed: Vec<Armed<P>>,
}

impl<P> DeadlineQueue<P> {
    /// # C: O(1)
    pub const fn new() -> Self { Self { armed: Vec::new() } }

    /// Arm `tid`, replacing any expiry it already had. Linux re-arms a live
    /// `hrtimer` by dequeue-then-enqueue (`__hrtimer_start_range_ns`
    /// `remove_and_enqueue_same_base`), and a task can be parked on at most one
    /// wait at a time, so the replaced entry is the only thing that keeps this
    /// bounded by the live task count. Returns the displaced payload.
    /// # C: O(N armed)
    pub fn arm(&mut self, tid: u32, soft_ns: u64, hard_ns: u64, payload: P) -> Option<P> {
        let displaced = self.disarm(tid);
        // Descending by hard expiry: find the first entry this one is not
        // later than, and take its place.
        let at = self.armed.partition_point(|a| a.hard_ns > hard_ns);
        self.armed.insert(at, Armed { soft_ns, hard_ns, tid, payload });
        displaced
    }

    /// Cancel `tid`'s expiry — Linux `hrtimer_cancel`. # C: O(N armed)
    pub fn disarm(&mut self, tid: u32) -> Option<P> {
        let at = self.armed.iter().position(|a| a.tid == tid)?;
        Some(self.armed.remove(at).payload)
    }

    /// Earliest armed HARD expiry, `u64::MAX` when nothing is armed — Linux
    /// `cpu_base->expires_next` seeded from `KTIME_MAX`. # C: O(1)
    pub fn earliest_hard_ns(&self) -> u64 {
        self.armed.last().map(|a| a.hard_ns).unwrap_or(u64::MAX)
    }

    /// Take the next expiry whose SOFT time has passed, Linux
    /// `__hrtimer_run_queues`' `if (basenow < hrtimer_get_softexpires(timer))
    /// break;`. Returns `None` while the earliest-hard entry
    /// is not yet soft-due, exactly as Linux stops the walk there — a later
    /// entry that IS soft-due is left for the interrupt its own hard expiry
    /// will raise anyway.
    /// # C: O(1)
    pub fn pop_soft_due(&mut self, now_ns: u64) -> Option<Armed<P>> {
        if self.armed.last()?.soft_ns > now_ns { return None; }
        self.armed.pop()
    }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.armed.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.armed.is_empty() }
}

impl<P> Default for DeadlineQueue<P> {
    fn default() -> Self { Self::new() }
}
