// Shared poll/ppoll helper (docs/53 §0). `monotonic_ns` is used by both
// the slot-7 poll handler and the slot-271 ppoll handler.
#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::sync::{Arc, Weak};

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
    /// Subscription id (the caller's tid, high-bit-tagged to never collide
    /// with epoll instance ids in a shared `PollSubscribers`). A task is in
    /// at most one poll/select at a time, so the tid is a stable key.
    id: u32,
}

impl PollWaiter {
    /// # C: O(1)
    pub(crate) fn new() -> Arc<Self> {
        let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
        Arc::new(Self { wq: Arc::new(sched::live::WaitList::new()), id: 0x8000_0000 | tid })
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

    /// Park the current task until a subscribed fd notifies us or
    /// `deadline_ns` passes (the latter only matters for polled fds with no
    /// event source — e.g. timerfd — and for the caller's timeout).
    /// # SAFETY: process ctx; preempt-off across the syscall; park marks
    /// Sleeping + stamps the deadline; tick_yield yields into the scheduler.
    /// # C: O(1) + ctxsw
    pub(crate) unsafe fn park_until(&self, deadline_ns: u64) {
        // SAFETY: caller (sys_poll/sys_select) is the running task on this CPU in process context, preempt-off; park_with_deadline marks it Sleeping + stamps the deadline, tick_yield reschedules.
        unsafe { self.wq.park_with_deadline(deadline_ns); sched::live::tick_yield(); }
    }
}

impl vfs::EpollNotify for PollWaiter {
    fn notify(&self) { self.wq.wake_all(); }
}
