// CPU-affinity mask composition — Linux keeps three masks per task and derives
// the effective one:
//
//   `task_struct::cpus_mask`      — effective; the ONLY mask the scheduler reads
//   `task_struct::user_cpus_ptr`  — what `sched_setaffinity(2)` last requested
//   `cpuset_cpus_allowed(p)`      — what the task's cpuset permits
//
// Both writers (the syscall and a cgroup `cpuset.cpus` write) derive
// `cpus_mask` HERE, so they cannot become a last-writer-wins pair that
// disagrees (`docs/53`, no split source of truth). The two writers do not
// compose identically, and that difference is a [`MaskChange`] argument rather
// than a second function that silently drifts.

/// Which writer is recomposing `cpus_allowed`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MaskChange {
    /// `sched_setaffinity(2)`: the caller named the mask it wants. Strict
    /// intersection with the cpuset, no substitution — an empty result is the
    /// caller's error (EINVAL) and must not be papered over, or a request for
    /// CPUs the cpuset forbids would silently succeed with a different mask.
    UserRequest,
    /// A cgroup `cpuset.cpus` write: the cpuset is authoritative and the parked
    /// `sched_setaffinity(2)` request is re-applied on top of it, but only when
    /// the two intersect. Disjoint leaves the cpuset alone in force — the
    /// kernel never parks a task on an empty, unschedulable mask, and the user
    /// request is retained so it takes effect again if the cpuset widens.
    CpusetUpdate,
}

/// Effective `cpus_allowed` for a task whose cpuset permits `cpuset` and whose
/// last `sched_setaffinity(2)` request was `user` (`0` = never called, i.e. no
/// `user_cpus_ptr`), for the writer named by `change`.
/// # C: O(1)
pub fn compose(cpuset: u64, user: u64, change: MaskChange) -> u64 {
    match change {
        MaskChange::UserRequest => cpuset & user,
        MaskChange::CpusetUpdate => {
            if user == 0 { return cpuset; }
            let both = cpuset & user;
            if both == 0 { cpuset } else { both }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{compose, MaskChange::{CpusetUpdate, UserRequest}};

    /// No `sched_setaffinity` yet: the cpuset alone decides.
    #[test]
    fn cpuset_alone_when_no_user_request() {
        assert_eq!(compose(0b0011, 0, CpusetUpdate), 0b0011);
        assert_eq!(compose(u64::MAX, 0, CpusetUpdate), u64::MAX);
    }

    /// The two compose by intersection, in either order of arrival.
    #[test]
    fn user_request_and_cpuset_intersect() {
        assert_eq!(compose(0b0011, 0b1111, CpusetUpdate), 0b0011);
        assert_eq!(compose(0b1111, 0b1010, CpusetUpdate), 0b1010);
        assert_eq!(compose(0b0110, 0b0011, CpusetUpdate), 0b0010);
        assert_eq!(compose(0b0110, 0b0011, UserRequest), 0b0010);
    }

    /// Disjoint under a cpuset write: the cpuset wins rather than the mask
    /// emptying — an empty `cpus_mask` would make the task permanently
    /// unschedulable, so the cpuset stays in force and the user request is
    /// merely dormant.
    #[test]
    fn disjoint_cpuset_update_falls_back_to_the_cpuset() {
        assert_eq!(compose(0b1100, 0b0011, CpusetUpdate), 0b1100);
        assert_ne!(compose(0b1100, 0b0011, CpusetUpdate), 0);
    }

    /// Disjoint under a `sched_setaffinity(2)` request: NO substitution. The
    /// empty result is what the syscall reports as EINVAL; substituting the
    /// cpuset here would make the call succeed while pinning the task to CPUs
    /// the caller never asked for.
    #[test]
    fn disjoint_user_request_stays_empty() {
        assert_eq!(compose(0b1100, 0b0011, UserRequest), 0);
    }

    /// A dormant user request revives when the cpuset widens to overlap it,
    /// which is why the request is parked instead of being erased.
    #[test]
    fn a_dormant_user_request_revives_when_the_cpuset_widens() {
        let user = 0b0011;
        assert_eq!(compose(0b1100, user, CpusetUpdate), 0b1100, "dormant");
        assert_eq!(compose(0b1111, user, CpusetUpdate), 0b0011, "revived");
    }
}
