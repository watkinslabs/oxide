// CPU-affinity mask composition — Linux keeps three masks per task and derives
// the effective one:
//
//   `task_struct::cpus_mask`      — effective; the ONLY mask the scheduler reads
//   `task_struct::user_cpus_ptr`  — what `sched_setaffinity(2)` last requested
//   `cpuset_cpus_allowed(p)`      — what the task's cpuset permits
//
// Keeping the derivation in one place is what stops `sched_setaffinity(2)` and
// a cgroup `cpuset.cpus` write from being a last-writer-wins pair that can
// disagree with each other (`docs/53`, no split source of truth).

/// Effective mask for a task whose cpuset permits `cpuset` and whose last
/// `sched_setaffinity(2)` request was `user` (`0` = never called, i.e. no
/// `user_cpus_ptr`). Linux `cpuset_update_tasks_cpus` narrows the cpuset by the
/// user's request; when the two are disjoint the cpuset wins, because Linux
/// never leaves a task on an empty, unschedulable mask.
/// # C: O(1)
pub fn compose(cpuset: u64, user: u64) -> u64 {
    if user == 0 { return cpuset; }
    let both = cpuset & user;
    if both == 0 { cpuset } else { both }
}

#[cfg(test)]
mod tests {
    use super::compose;

    /// No `sched_setaffinity` yet: the cpuset alone decides.
    #[test]
    fn cpuset_alone_when_no_user_request() {
        assert_eq!(compose(0b0011, 0), 0b0011);
        assert_eq!(compose(u64::MAX, 0), u64::MAX);
    }

    /// The two compose by intersection, in either order of arrival.
    #[test]
    fn user_request_and_cpuset_intersect() {
        assert_eq!(compose(0b0011, 0b1111), 0b0011);
        assert_eq!(compose(0b1111, 0b1010), 0b1010);
        assert_eq!(compose(0b0110, 0b0011), 0b0010);
    }

    /// Disjoint: the cpuset wins rather than the mask emptying — an empty
    /// `cpus_mask` would make the task permanently unschedulable.
    #[test]
    fn disjoint_falls_back_to_the_cpuset() {
        assert_eq!(compose(0b1100, 0b0011), 0b1100);
        assert_ne!(compose(0b1100, 0b0011), 0);
    }
}
