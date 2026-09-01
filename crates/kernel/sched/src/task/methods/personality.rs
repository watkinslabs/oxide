use core::sync::atomic::Ordering;
use sync::{Spinlock, TaskList as TaskListClass};

use crate::Task;

impl Task {
    /// Publish the execution personality at the PE task commit point.
    /// # C: O(1)
    pub fn set_nt_personality(&self, enabled: bool) {
        self.security.nt_personality.store(enabled, Ordering::Release);
    }

    /// Read the execution personality selected for this task.
    /// # C: O(1)
    pub fn is_nt_personality(&self) -> bool {
        self.security.nt_personality.load(Ordering::Acquire)
    }

    /// Publish the PEB address created by the NT PE environment builder. # C: O(1)
    pub fn set_nt_peb(&self, peb: u64) { self.core.nt_peb.store(peb, Ordering::Release); }

    /// Read the task-owned PEB address for native process queries. # C: O(1)
    pub fn nt_peb(&self) -> u64 { self.core.nt_peb.load(Ordering::Acquire) }

    /// Publish the TEB address created for this NT thread. # C: O(1)
    pub fn set_nt_teb(&self, teb: u64) { self.core.nt_teb.store(teb, Ordering::Release); }

    /// Read the task-owned TEB address for native thread queries. # C: O(1)
    pub fn nt_teb(&self) -> u64 { self.core.nt_teb.load(Ordering::Acquire) }

    /// Access thread-local Windows preferred UI-language state. # C: O(1)
    pub fn nt_thread_ui_languages(&self) -> &Spinlock<(u32, alloc::vec::Vec<u16>), TaskListClass> { &self.core.nt_thread_ui_languages }

    /// Read the canonical NT job identity for this process. # C: O(1)
    pub fn nt_job_id(&self) -> u64 { self.core.nt_job_id.load(Ordering::Acquire) }

    /// Assign this process to one native NT job identity. # C: O(1)
    pub fn set_nt_job_id(&self, job: u64) { self.core.nt_job_id.store(job, Ordering::Release); }
}
