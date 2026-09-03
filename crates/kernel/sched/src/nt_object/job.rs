//! State owned by one native NT job object.

use sync::{Spinlock, TaskList as TaskListClass};

/// The limit state shared by all handles referring to one job object.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct NtJobLimits {
    pub flags: u32,
    pub active_process_limit: u32,
    pub process_memory_limit: u64,
    pub job_memory_limit: u64,
}

/// Mutable job state is object-owned and protected independently of the
/// process handle table, so duplicate handles observe one consistent object.
pub struct NtJob { limits: Spinlock<NtJobLimits, TaskListClass> }

impl NtJob {
    pub fn new() -> Self { Self { limits: Spinlock::new(NtJobLimits::default()) } }
    pub fn limits(&self) -> NtJobLimits { *self.limits.lock() }
    pub fn set_limits(&self, limits: NtJobLimits) { *self.limits.lock() = limits; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_shared_by_the_object_owner() {
        let job = NtJob::new();
        let limits = NtJobLimits { flags: 0x2008, active_process_limit: 4,
            process_memory_limit: 0x1000, job_memory_limit: 0x2000 };
        job.set_limits(limits);
        assert_eq!(job.limits(), limits);
    }
}
