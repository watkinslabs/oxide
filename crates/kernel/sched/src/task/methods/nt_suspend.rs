use core::sync::atomic::Ordering;

use crate::Task;

impl Task {
    /// Decrease the NT suspend depth without allowing an underflow. Returns
    /// the depth observed before the resume request. # C: O(1)
    pub fn nt_resume(&self) -> u32 {
        self.nt_suspend_count.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |count| Some(count.saturating_sub(1))).unwrap_or(0)
    }
}
