// Live-scheduler realisation of the socket sleep queue. Parks the running
// task on the scheduler's generic wait list and yields through the single
// `schedule()` switch primitive.

/// # C: O(1) park / O(N_waiters) wake
pub struct SockWaitQueue {
    inner: sched::live::WaitList,
}

impl SockWaitQueue {
    /// # C: O(1)
    pub const fn new() -> Self { Self { inner: sched::live::WaitList::new() } }

    /// Named lock-coupled interruptible publication with an absolute deadline.
    /// # SAFETY: caller holds the resource lock shared with its waker and
    /// schedules immediately after dropping that lock.
    /// # C: O(N armed)
    pub unsafe fn prepare_to_wait_interruptible_with_deadline(&self, deadline_ns: u64) {
        // SAFETY: preserves the socket queue's prepared-wait contract while
        // forwarding the deadline to the scheduler-owned wait list.
        unsafe { self.inner.prepare_to_wait_interruptible_with_deadline(deadline_ns); }
    }

    /// Yield until a wake lands or the published expiry fires — the reference
    /// stack's `schedule_timeout` step.
    /// # SAFETY: caller is at a safe schedule point: no lock held that a waker
    /// needs, preemption owned by the syscall context that parked.
    /// # C: O(log N) CFS pick + O(1) context switch
    pub unsafe fn wait(&self) {
        // SAFETY: the park above published this task as Sleeping; this is the
        // one task-switch primitive and the caller owns the schedule point.
        unsafe { sched::live::schedule::schedule(); }
    }

    /// Retire the running task's registration after wake, signal, or timeout —
    /// the reference stack's `finish_wait`.
    /// # C: O(N_waiters)
    pub fn remove_current(&self) { self.inner.remove_current(); }

    /// Cancel a published park before the yield, restoring runnability.
    /// # C: O(N_waiters)
    pub fn cancel_current_park(&self) { self.inner.cancel_current_park(); }

    /// # C: O(1)
    pub fn wake_one(&self) { self.inner.wake_one(); }

    /// # C: O(N_waiters)
    pub fn wake_all(&self) { self.inner.wake_all(); }

    /// # C: O(1)
    pub fn has_waiters(&self) -> bool { self.inner.has_waiters() }
}

impl Default for SockWaitQueue {
    fn default() -> Self { Self::new() }
}
