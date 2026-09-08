//! Budget for the failing-open trace at the NT file boundary.
//!
//! A loader walks a search path and most candidates on it are absent, so the
//! trace has to be capped or one failing load buries the log. A cap shared by
//! every process on the machine is the wrong cap: the processes that start
//! first spend it, and the one whose failure is being chased then produces no
//! line at all — an absence indistinguishable from "the open never happened".
//! The budget therefore belongs to the process being traced, and the first
//! failing open of a new process starts a fresh one.

/// What one failing open should do, and the budget state that follows it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct TraceBudget {
    pub(crate) report: bool,
    pub(crate) owner: u64,
    pub(crate) used: u32,
}

/// Charge one failing open against the budget. A process that is not the
/// budget's owner takes it over with a full one. # C: O(1)
pub(crate) const fn charge(owner: u64, used: u32, current: u64, cap: u32) -> TraceBudget {
    if current != owner { return TraceBudget { report: cap > 0, owner: current, used: 1 }; }
    if used < cap { return TraceBudget { report: true, owner, used: used + 1 }; }
    TraceBudget { report: false, owner, used }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CAP: u32 = 4;

    /// The process whose failure is being chased must get its own lines even
    /// when every earlier process together spent far more than the cap.
    #[test]
    fn a_new_process_starts_with_a_full_budget() {
        let spent = TraceBudget { report: false, owner: 7, used: u32::MAX };
        let next = charge(spent.owner, spent.used, 9, CAP);
        assert_eq!(next, TraceBudget { report: true, owner: 9, used: 1 });
    }

    #[test]
    fn one_process_spends_its_budget_once_and_then_stays_quiet() {
        let mut state = TraceBudget { report: false, owner: 3, used: 0 };
        for expected in 1..=CAP {
            state = charge(state.owner, state.used, 3, CAP);
            assert!(state.report);
            assert_eq!(state.used, expected);
        }
        state = charge(state.owner, state.used, 3, CAP);
        assert!(!state.report);
        assert_eq!(state.used, CAP);
        // And the next process is unaffected by what this one spent.
        let other = charge(state.owner, state.used, 4, CAP);
        assert!(other.report);
        assert_eq!(other.used, 1);
    }

    #[test]
    fn a_zero_cap_reports_nothing_at_all() {
        assert!(!charge(0, 0, 5, 0).report);
        assert!(!charge(5, 0, 5, 0).report);
    }
}
