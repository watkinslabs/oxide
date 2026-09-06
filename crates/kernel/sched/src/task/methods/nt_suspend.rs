use core::sync::atomic::Ordering;

use crate::Task;

/// Windows/Wine's maximum per-thread suspend depth.
pub const NT_MAX_SUSPEND_COUNT: u32 = 127;

impl Task {
    /// Increase the NT suspend depth, returning the prior depth or overflow. # C: O(1)
    pub fn nt_suspend(&self) -> Result<u32, ()> {
        let result = self.nt_suspend_count.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |count| (count < NT_MAX_SUSPEND_COUNT).then_some(count + 1));
        match result {
            Ok(previous) => {
                if previous == 0 {
                    crate::preempt::resched::set_tsk_need_resched(self);
                    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                    if self.on_cpu.load(Ordering::Acquire) {
                        crate::live::ttwu::resched_curr(self.cpu.load(Ordering::Acquire) as u32);
                    }
                }
                Ok(previous)
            }
            Err(_) => Err(()),
        }
    }

    /// Decrease the NT suspend depth without allowing an underflow. Returns
    /// the depth observed before the resume request. # C: O(1)
    pub fn nt_resume(&self) -> u32 {
        self.nt_suspend_count.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |count| Some(count.saturating_sub(1))).unwrap_or(0)
    }

    /// Whether this task owes its own NT suspension checkpoint. # C: O(1)
    pub fn nt_suspend_requested(&self) -> bool {
        self.nt_suspend_count.load(Ordering::Acquire) != 0
    }

    /// Claim the single activation of an off-runqueue NT child. # C: O(1)
    pub fn claim_nt_initial_wake(&self) -> bool {
        if self.nt_creation_pending.load(Ordering::Acquire) || self.nt_suspend_requested()
            || self.on_rq.load(Ordering::Acquire) || self.on_cpu.load(Ordering::Acquire) { return false; }
        self.cas_state(crate::TaskState::Runnable, crate::TaskState::Waking).is_ok()
    }

    /// Claim a sleeping task for the final NT resume. # C: O(1)
    pub(crate) fn claim_nt_wake(&self) -> bool {
        if self.nt_suspend_requested() { return false; }
        let mut seen = self.state.load(Ordering::Acquire);
        loop {
            if crate::TaskState::from_u8(seen) != Some(crate::TaskState::Sleeping) { return false; }
            if !self.nt_suspend_ack.load(Ordering::Acquire)
                && !self.nt_wake_pending.load(Ordering::Acquire) { return false; }
            let next = (seen & !crate::TaskState::LIFECYCLE_MASK) | crate::TaskState::Waking as u8;
            match self.state.compare_exchange_weak(seen, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    self.nt_suspend_ack.store(false, Ordering::Release);
                    self.nt_wake_pending.store(false, Ordering::Release);
                    return true;
                }
                Err(now) => seen = now,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SchedClass, TaskState, WaitState};

    #[test]
    fn suspend_depth_matches_native_bound_and_reports_prior_value() {
        let task = alloc::sync::Arc::new(Task::new(98_421, "nt-suspend", SchedClass::Normal { weight: 1024 }));
        for expected in 0..NT_MAX_SUSPEND_COUNT { assert_eq!(task.nt_suspend(), Ok(expected)); }
        assert_eq!(task.nt_suspend(), Err(()));
        assert_eq!(task.nt_suspend_count.load(Ordering::Acquire), NT_MAX_SUSPEND_COUNT);
    }

    #[test]
    fn ordinary_wake_is_deferred_while_native_suspend_is_active() {
        let task = alloc::sync::Arc::new(Task::new(98_422, "nt-wake", SchedClass::Normal { weight: 1024 }));
        task.set_sleep_state(WaitState::Uninterruptible);
        assert_eq!(task.nt_suspend(), Ok(0));
        assert!(!task.claim_wake());
        assert!(task.nt_wake_pending.load(Ordering::Acquire));
        assert!(!task.claim_nt_wake(), "resume wake requires the final depth release");
        assert_eq!(task.nt_resume(), 1);
        assert!(task.claim_nt_wake());
        assert_eq!(task.state(), TaskState::Waking);
    }
}
