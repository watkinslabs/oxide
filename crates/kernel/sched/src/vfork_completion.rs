//! Child-owned completion used by `CLONE_VFORK`.

use core::sync::atomic::{AtomicBool, Ordering};

/// Linux-shaped completion state stored in the child task.
pub struct VforkCompletion {
    pending: AtomicBool,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    wait: crate::live::WaitList,
}

impl VforkCompletion {
    /// Build an inactive child-owned completion. # C: O(1)
    pub const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            wait: crate::live::WaitList::new(),
        }
    }

    /// Arm the completion before the child becomes visible. # C: O(1)
    pub fn arm(&self) { self.pending.store(true, Ordering::Release); }

    /// Read whether the child has released the completion. # C: O(1)
    pub fn is_complete(&self) -> bool { !self.pending.load(Ordering::Acquire) }

    /// Complete once and wake a parent that has already started waiting.
    /// # C: O(1) + one wake fan-out
    pub fn complete(&self) -> bool {
        if !self.pending.swap(false, Ordering::AcqRel) { return false; }
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        self.wait.wake_all();
        true
    }

    /// Wait until the child releases its borrowed address space.
    /// # SAFETY: process context owns no lock required by `complete`.
    /// # C: O(N_wakeups) plus sleeps
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait(&self) -> bool {
        matches!(unsafe { crate::live::wait_event_killable(&self.wait,
            || self.is_complete()) }, crate::WaitOutcome::Ready)
    }
}
