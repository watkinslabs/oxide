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
/// # C: O(words)
pub fn compose(cpuset: cpu::CpuMask, user: cpu::CpuMask, change: MaskChange) -> cpu::CpuMask {
    match change {
        MaskChange::UserRequest => cpuset.intersect(user),
        MaskChange::CpusetUpdate => {
            if user.is_empty() { return cpuset; }
            let both = cpuset.intersect(user);
            if both.is_empty() { cpuset } else { both }
        }
    }
}

#[cfg(test)]
mod tests {
    use cpu::CpuMask;
    use super::{compose, MaskChange::{CpusetUpdate, UserRequest}};

    fn m(bits: u64) -> CpuMask { CpuMask::from_words(&[bits]) }

    /// No `sched_setaffinity` yet: the cpuset alone decides.
    #[test]
    fn cpuset_alone_when_no_user_request() {
        assert_eq!(compose(m(0b0011), CpuMask::empty(), CpusetUpdate), m(0b0011));
        assert_eq!(compose(CpuMask::all(), CpuMask::empty(), CpusetUpdate), CpuMask::all());
    }

    /// The two compose by intersection, in either order of arrival.
    #[test]
    fn user_request_and_cpuset_intersect() {
        assert_eq!(compose(m(0b0011), m(0b1111), CpusetUpdate), m(0b0011));
        assert_eq!(compose(m(0b1111), m(0b1010), CpusetUpdate), m(0b1010));
        assert_eq!(compose(m(0b0110), m(0b0011), CpusetUpdate), m(0b0010));
        assert_eq!(compose(m(0b0110), m(0b0011), UserRequest), m(0b0010));
    }

    /// Disjoint under a cpuset write: the cpuset wins rather than the mask
    /// emptying — an empty `cpus_mask` would make the task permanently
    /// unschedulable, so the cpuset stays in force and the user request is
    /// merely dormant.
    #[test]
    fn disjoint_cpuset_update_falls_back_to_the_cpuset() {
        assert_eq!(compose(m(0b1100), m(0b0011), CpusetUpdate), m(0b1100));
        assert_ne!(compose(m(0b1100), m(0b0011), CpusetUpdate), CpuMask::empty());
    }

    /// Disjoint under a `sched_setaffinity(2)` request: NO substitution. The
    /// empty result is what the syscall reports as EINVAL; substituting the
    /// cpuset here would make the call succeed while pinning the task to CPUs
    /// the caller never asked for.
    #[test]
    fn disjoint_user_request_stays_empty() {
        assert_eq!(compose(m(0b1100), m(0b0011), UserRequest), CpuMask::empty());
    }

    /// A dormant user request revives when the cpuset widens to overlap it,
    /// which is why the request is parked instead of being erased.
    #[test]
    fn a_dormant_user_request_revives_when_the_cpuset_widens() {
        let user = m(0b0011);
        assert_eq!(compose(m(0b1100), user, CpusetUpdate), m(0b1100), "dormant");
        assert_eq!(compose(m(0b1111), user, CpusetUpdate), m(0b0011), "revived");
    }
}
