//! Task-owned terminal completion used by native NT process and thread waits.

use core::sync::atomic::{AtomicBool, Ordering};

/// One-way completion published when a task enters its terminal state.
pub struct NtTermination {
    completed: AtomicBool,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: crate::live::WaitList,
}

impl NtTermination {
    /// Construct an incomplete task termination record. # C: O(1)
    pub const fn new() -> Self {
        Self {
            completed: AtomicBool::new(false),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: crate::live::WaitList::new(),
        }
    }

    /// Publish terminal state once and wake every NT waiter. # C: O(N_waiters)
    pub fn complete(&self) -> bool {
        if self.completed.swap(true, Ordering::AcqRel) { return false; }
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        self.waiters.wake_all();
        true
    }

    /// Test whether the task has reached its terminal state. # C: O(1)
    pub fn is_complete(&self) -> bool { self.completed.load(Ordering::Acquire) }

    /// Wait for task termination with native NT timeout semantics. # C: O(N_wakeups)
    /// # SAFETY: caller is process context and retains the task identity.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        // SAFETY: this task-owned wait list outlives the predicate wait and
        // completion has no lock that the scheduler wake path must acquire.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now, || self.is_complete()) }
    }

    /// Alertable wait variant returning the native APC outcome. # C: O(N_wakeups)
    /// # SAFETY: caller is process context and retains the task identity.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait_alertable(&self, deadline_ns: u64, now: impl Fn() -> u64,
                                 apc: impl FnMut() -> bool) -> crate::NtWaitOutcome {
        // SAFETY: forwarded to the shared alertable wait loop with a stable
        // task-owned completion predicate and no caller lock held.
        unsafe { crate::live::wait_event_interruptible_until_user_apc(
            &self.waiters, deadline_ns, now, apc, || self.is_complete()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_is_one_way_and_shared_by_all_waiters() {
        let completion = NtTermination::new();
        assert!(!completion.is_complete());
        assert!(completion.complete());
        assert!(completion.is_complete());
        assert!(!completion.complete());
        assert!(matches!(unsafe { completion.wait(0, || 0) }, crate::WaitOutcome::Ready));
    }

    #[test]
    fn incomplete_task_wait_honors_an_expired_deadline() {
        let completion = NtTermination::new();
        assert!(matches!(unsafe { completion.wait(10, || 10) }, crate::WaitOutcome::TimedOut));
    }
}
