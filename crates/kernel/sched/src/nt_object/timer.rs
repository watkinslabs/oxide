//! Waitable NT timer state, driven by the scheduler's monotonic clock.

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use crate::live::WaitList;

const DISARMED: u64 = u64::MAX;

/// Combine a caller timeout with an armed timer expiry. Zero means no caller
/// timeout; it must not hide the timer's own absolute deadline. # C: O(1)
pub fn merge_wait_deadline(wait_deadline: u64, timer_deadline: Option<u64>) -> u64 {
    match (wait_deadline, timer_deadline) {
        (0, Some(timer)) => timer,
        (0, None) => 0,
        (wait, Some(timer)) => wait.min(timer),
        (wait, None) => wait,
    }
}

pub struct NtTimer {
    manual_reset: bool,
    due_ns: AtomicU64,
    period_ns: AtomicU64,
    signaled: AtomicBool,
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    waiters: WaitList,
}

impl NtTimer {
    pub fn new(manual_reset: bool) -> Self {
        Self { manual_reset, due_ns: AtomicU64::new(DISARMED), period_ns: AtomicU64::new(0), signaled: AtomicBool::new(false),
            #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
            waiters: WaitList::new() }
    }

    /// Arm a relative timer. A zero period makes it one-shot. # C: O(1)
    pub fn arm(&self, due_ns: u64, period_ns: u64) {
        self.signaled.store(false, Ordering::Release);
        self.period_ns.store(period_ns, Ordering::Release);
        self.due_ns.store(due_ns, Ordering::Release);
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        self.waiters.wake_all();
    }

    /// Disarm the timer and return whether it had been signaled. # C: O(1)
    pub fn cancel(&self) -> bool {
        self.due_ns.store(DISARMED, Ordering::Release);
        self.period_ns.store(0, Ordering::Release);
        let was_signaled = self.signaled.swap(false, Ordering::AcqRel);
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        self.waiters.wake_all();
        was_signaled
    }

    pub fn due_ns(&self) -> u64 { self.due_ns.load(Ordering::Acquire) }

    /// Return the armed absolute expiry, omitting the disarmed sentinel. # C: O(1)
    pub fn deadline(&self) -> Option<u64> {
        match self.due_ns() { DISARMED => None, due => Some(due) }
    }

    pub fn is_signaled_at(&self, now_ns: u64) -> bool {
        if self.signaled.load(Ordering::Acquire) { return true; }
        let due = self.due_ns.load(Ordering::Acquire);
        if due == DISARMED || now_ns < due { return false; }
        self.signaled.store(true, Ordering::Release);
        let period = self.period_ns.load(Ordering::Acquire);
        if period == 0 { self.due_ns.store(DISARMED, Ordering::Release); }
        else { self.due_ns.store(due.saturating_add(period), Ordering::Release); }
        true
    }

    pub fn try_wait_at(&self, now_ns: u64) -> bool {
        if !self.is_signaled_at(now_ns) { return false; }
        if self.manual_reset { true }
        else { self.signaled.compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire).is_ok() }
    }

    /// Wait until the timer fires or the caller's deadline expires. # C: sleeps
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        loop {
            let current = now();
            if self.try_wait_at(current) { return crate::WaitOutcome::Ready; }
            let timer_deadline = self.deadline();
            let wake_at = merge_wait_deadline(deadline_ns, timer_deadline);
            let outcome = unsafe { crate::live::wait_event_interruptible_until(&self.waiters, wake_at, &now, || self.try_wait_at(now())) };
            if matches!(outcome, crate::WaitOutcome::TimedOut) && timer_deadline == Some(wake_at) { continue; }
            return outcome;
        }
    }

    /// Alertable timer wait with a distinct native APC outcome. # C: sleeps
    /// # SAFETY: caller is process context and keeps this object alive.
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    pub unsafe fn wait_alertable(&self, deadline_ns: u64, now: impl Fn() -> u64,
                                 mut apc: impl FnMut() -> bool) -> crate::NtWaitOutcome {
        loop {
            let current = now();
            if self.try_wait_at(current) { return crate::NtWaitOutcome::Ready; }
            let timer_deadline = self.deadline();
            let wake_at = merge_wait_deadline(deadline_ns, timer_deadline);
            // SAFETY: forwarded to the scheduler alertable wait contract.
            let outcome = unsafe { crate::live::wait_event_interruptible_until_user_apc(
                &self.waiters, wake_at, &now, &mut apc, || self.try_wait_at(now())) };
            if matches!(outcome, crate::NtWaitOutcome::TimedOut) && timer_deadline == Some(wake_at) { continue; }
            return outcome;
        }
    }
}
