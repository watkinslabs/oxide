// Shared poll/ppoll helper (docs/53 §0). `monotonic_ns` is used by both
// the slot-7 poll handler and the slot-271 ppoll handler.
#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

/// # C: O(1) monotonic clock read
#[inline]
pub(crate) fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// The Linux `->poll` waiter for one poll/select/ppoll call. Mirrors
/// `fs::EpollInode`: poll/select subscribe this (as `vfs::EpollNotify`)
/// to each polled fd's `PollSubscribers`; the fd's readiness transition
/// `notify()`s ONLY its subscribers, which wakes this waiter's `WaitList`
/// — targeted, no global broadcast. The calling task parks on `wq`.
pub(crate) struct PollWaiter {
    wq: Arc<sched::live::WaitList>,
    generation: AtomicU64,
    /// Subscription id (the caller's tid, high-bit-tagged to never collide
    /// with epoll instance ids in a shared `PollSubscribers`). A task is in
    /// at most one poll/select at a time, so the tid is a stable key.
    id: u32,
}

impl PollWaiter {
    /// # C: O(1)
    pub(crate) fn new() -> Arc<Self> {
        let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
        Arc::new(Self {
            wq: Arc::new(sched::live::WaitList::new()),
            generation: AtomicU64::new(0),
            id: 0x8000_0000 | tid,
        })
    }

    /// Register on `subs` (one polled fd's wait queue). # C: O(N_subs)
    pub(crate) fn subscribe(self: &Arc<Self>, subs: &vfs::PollSubscribers) {
        let weak: Weak<dyn vfs::EpollNotify> =
            Arc::downgrade(&(Arc::clone(self) as Arc<dyn vfs::EpollNotify>));
        subs.subscribe(self.id, weak);
    }

    /// Drop the registration from `subs`. # C: O(N_subs)
    pub(crate) fn unsubscribe(&self, subs: &vfs::PollSubscribers) {
        subs.unsubscribe(self.id);
    }

    /// Snapshot the notification sequence before a readiness scan. # C: O(1)
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Park the current task until a subscribed fd notifies us or
    /// `deadline_ns` passes. The caller snapshots `generation` before its
    /// readiness scan; a notification in the scan-to-park window is observed
    /// after Sleeping is installed and immediately wakes the task.
    /// # SAFETY: process ctx; preempt-off across the syscall; park marks
    /// Sleeping + stamps the deadline; park_yield yields into the scheduler.
    /// # C: O(1) + ctxsw
    pub(crate) unsafe fn park_until(&self, observed: u64, deadline_ns: u64) {
        // `select_estimate_accuracy`, not the flat task slack: Linux hands
        // poll(2)/select(2) 0.1% of the remaining timeout as coalescing range
        // (from `poll_schedule_timeout` →
        // `schedule_hrtimeout_range(expires, slack, HRTIMER_MODE_ABS)`), which
        // is what keeps a machine full of long pollers off the interrupt path.
        let slack_ns = sched::hrtimeout::select_estimate_accuracy(deadline_ns);
        // SAFETY: caller (sys_poll/sys_select) is the running task on this CPU in process context, preempt-off; park_with_deadline_range publishes Sleeping on this wait list before the generation recheck.
        unsafe { self.wq.park_with_deadline_range(deadline_ns, slack_ns); }
        if self.generation.load(Ordering::Acquire) != observed {
            self.wq.wake_all();
        }
        // SAFETY: current is Sleeping or was made Runnable by a racing source; the scheduler completes the handoff in either case.
        unsafe { sched::live::park_yield(); }
    }
}

impl vfs::EpollNotify for PollWaiter {
    fn notify(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.wq.wake_all();
    }
}
