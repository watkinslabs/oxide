// Why a task is parked in the freezer.
//
// Two independent subsystems park tasks with the same mechanism — the cgroup
// v2 freezer and the system-sleep freezer (`32a§10`) — and each must be able
// to release its own claim without resuming a task the other still holds. One
// bitmask per task, rather than a second `frozen` flag beside the first, which
// would be a split source of truth about whether a task may run.

/// `cgroup.freeze=1` on the task's cgroup.
pub const CGROUP: u8 = 1 << 0;
/// The system-sleep freeze pass (`32a§10`).
pub const SLEEP: u8 = 1 << 1;

/// Every reason a task can be parked for. # C: O(1)
pub const ALL: u8 = CGROUP | SLEEP;

/// The reasons remaining after `reason` releases its claim on `held`.
/// # C: O(1)
pub fn release(held: u8, reason: u8) -> u8 { held & !reason }

/// Whether a task holding `reasons` stays parked. # C: O(1)
pub fn still_parked(reasons: u8) -> bool { reasons != 0 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releasing_one_reason_leaves_the_other_holding() {
        let held = CGROUP | SLEEP;
        assert!(still_parked(release(held, SLEEP)), "the sleep thaw resumed a cgroup-frozen task");
        assert!(still_parked(release(held, CGROUP)));
    }

    #[test]
    fn releasing_the_last_reason_resumes_the_task() {
        assert!(!still_parked(release(CGROUP, CGROUP)));
        assert!(!still_parked(release(SLEEP, SLEEP)));
    }

    #[test]
    fn releasing_a_reason_never_claimed_is_a_no_op() {
        assert_eq!(release(CGROUP, SLEEP), CGROUP);
        assert_eq!(release(0, ALL), 0);
    }

    #[test]
    fn the_reasons_are_distinct_bits() {
        assert_eq!(CGROUP & SLEEP, 0);
        assert_eq!(ALL, CGROUP | SLEEP);
    }
}
