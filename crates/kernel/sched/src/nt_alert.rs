//! Per-thread alert flag behind the native alert-by-thread-id services.
//!
//! The published contract is a single auto-reset flag per thread: an alert
//! raises it and wakes the thread, and a wait consumes it. A wait that finds
//! the flag already raised returns immediately without sleeping, so an alert
//! that lands before its wait is never lost. This is the same flag the Win32
//! address-wait primitives are built on top of, which is why it is a thread
//! property rather than an object.

use core::sync::atomic::{AtomicBool, Ordering};

/// One thread's alert flag and the sleepers parked on it.
pub struct NtAlert {
    alerted: AtomicBool,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: crate::live::WaitList,
}

impl Default for NtAlert {
    fn default() -> Self { Self::new() }
}

impl NtAlert {
    /// Construct a thread alert flag in its cleared state. # C: O(1)
    pub const fn new() -> Self {
        Self {
            alerted: AtomicBool::new(false),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: crate::live::WaitList::new(),
        }
    }

    /// Raise the flag and wake the owning thread. Reports whether this call
    /// was the one that raised it; a second alert before the wait consumes
    /// the first is absorbed, exactly as an auto-reset flag absorbs it.
    /// # C: O(N_waiters)
    pub fn alert(&self) -> bool {
        let raised = !self.alerted.swap(true, Ordering::AcqRel);
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        self.waiters.wake_all();
        raised
    }

    /// Consume the flag, reporting whether it was raised. # C: O(1)
    pub fn consume(&self) -> bool { self.alerted.swap(false, Ordering::AcqRel) }

    /// Whether the flag is currently raised. # C: O(1)
    pub fn is_alerted(&self) -> bool { self.alerted.load(Ordering::Acquire) }

    /// Wait until this thread's flag is raised, consuming it. A deadline of
    /// zero waits without a timeout. # C: O(N_wakeups)
    /// # SAFETY: caller is process context and owns this thread's flag.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        // SAFETY: the flag is owned by the waiting task, outlives the wait,
        // and the waker holds no lock this predicate needs.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now, || self.consume()) }
    }
}

#[cfg(test)]
#[path = "nt_alert/tests.rs"]
mod tests;
