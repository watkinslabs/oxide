//! Hung-task detector policy — the reference's `khungtaskd`.
//!
//! A task in an UNINTERRUPTIBLE sleep that has not been switched out once in
//! `hung_task_timeout_secs` is not waiting, it is stuck: the wake it is
//! waiting for is never coming, or the lock it wants is never released. The
//! reference reports it, names it, and optionally panics.
//!
//! This module is the DECISION half and carries no target gate, so the whole
//! contract is exercised hosted. The kthread that drives it lives in
//! [`crate::live::khungtaskd`], and the site a reported task is parked at
//! comes from [`crate::park_site`].
//!
//! Killable and interruptible sleeps are skipped for the reference's reason:
//! a signal ends them, so they are not stuck in the sense this detector means.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::task::WaitState;
use crate::TaskState;

/// `CONFIG_DEFAULT_HUNG_TASK_TIMEOUT`. # C: O(1)
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// `sysctl_hung_task_warnings` — reports emitted before the detector goes
/// quiet, so a machine with a hundred stuck tasks does not drown its own log.
pub const DEFAULT_WARNINGS: u32 = 10;
/// Nanoseconds in a second, for the seconds-denominated knobs.
const NS_PER_SEC: u64 = 1_000_000_000;

static TIMEOUT_SECS: AtomicU64 = AtomicU64::new(DEFAULT_TIMEOUT_SECS);
static WARNINGS_LEFT: AtomicU32 = AtomicU32::new(DEFAULT_WARNINGS);
static PANIC_ON_HUNG: AtomicBool = AtomicBool::new(false);
/// `sysctl_hung_task_detect_count`: total reports since boot, which a consumer
/// reads to learn the machine hit this at all.
static DETECT_COUNT: AtomicU64 = AtomicU64::new(0);

/// What one scan of one task concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not a candidate: running, runnable, dead, or in a sleep a signal ends.
    Skip,
    /// A candidate that HAS switched since the last scan — record the new
    /// count and timestamp, and say nothing.
    Progressed,
    /// Blocked uninterruptibly, no context switch for the whole window.
    Hung,
}

/// One task's observation, named so a caller cannot transpose the two
/// switch counts or the two timestamps.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub state: TaskState,
    pub wait: WaitState,
    /// `nvcsw + nivcsw`.
    pub switch_count: u64,
    /// What the previous scan recorded, `0` before any scan.
    pub last_switch_count: u64,
    /// Monotonic time the previous scan recorded the count at.
    pub last_switch_ns: u64,
    pub now_ns: u64,
}

/// The reference's `task_is_hung`, split from its bookkeeping so the decision
/// itself is a pure function.
///
/// A task whose `switch_count` is zero is skipped: a freshly created task that
/// was scheduled once and set itself uninterruptible has never been switched
/// out, so its zero timestamp would read as "hung since the epoch".
/// # C: O(1)
pub fn classify(o: Observation, timeout_secs: u64) -> Verdict {
    if !matches!(o.state, TaskState::Sleeping) { return Verdict::Skip; }
    // `TASK_WAKEKILL` and `TASK_INTERRUPTIBLE` both end on a signal.
    if !matches!(o.wait, WaitState::Uninterruptible) { return Verdict::Skip; }
    if o.switch_count == 0 { return Verdict::Skip; }
    if timeout_secs == 0 { return Verdict::Skip; }
    if o.switch_count != o.last_switch_count { return Verdict::Progressed; }
    let deadline = o.last_switch_ns.saturating_add(timeout_secs.saturating_mul(NS_PER_SEC));
    if o.now_ns < deadline { return Verdict::Skip; }
    Verdict::Hung
}

/// Seconds a task may sleep uninterruptibly before it is reported. `0`
/// disables the detector, as `kernel.hung_task_timeout_secs` does. # C: O(1)
pub fn timeout_secs() -> u64 { TIMEOUT_SECS.load(Ordering::Relaxed) }

/// # C: O(1)
pub fn set_timeout_secs(secs: u64) { TIMEOUT_SECS.store(secs, Ordering::Relaxed); }

/// # C: O(1)
pub fn panic_on_hung() -> bool { PANIC_ON_HUNG.load(Ordering::Relaxed) }

/// # C: O(1)
pub fn set_panic_on_hung(on: bool) { PANIC_ON_HUNG.store(on, Ordering::Relaxed); }

/// Total tasks reported since boot. # C: O(1)
pub fn detect_count() -> u64 { DETECT_COUNT.load(Ordering::Relaxed) }

/// Claim one of the bounded report budget. `false` once the budget is spent,
/// which is how the detector stops repeating itself every scan forever.
/// # C: O(1)
pub fn claim_report() -> bool {
    DETECT_COUNT.fetch_add(1, Ordering::Relaxed);
    WARNINGS_LEFT.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                               |left| left.checked_sub(1)).is_ok()
}

/// Reports still available. # C: O(1)
pub fn warnings_left() -> u32 { WARNINGS_LEFT.load(Ordering::Relaxed) }

/// Restore the boot defaults. Hosted tests share process-wide statics.
#[cfg(test)]
fn reset() {
    TIMEOUT_SECS.store(DEFAULT_TIMEOUT_SECS, Ordering::Relaxed);
    WARNINGS_LEFT.store(DEFAULT_WARNINGS, Ordering::Relaxed);
    PANIC_ON_HUNG.store(false, Ordering::Relaxed);
    DETECT_COUNT.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = NS_PER_SEC;

    fn blocked(last_switch_ns: u64, now_ns: u64) -> Observation {
        Observation {
            state: TaskState::Sleeping, wait: WaitState::Uninterruptible,
            switch_count: 7, last_switch_count: 7, last_switch_ns, now_ns,
        }
    }

    #[test]
    fn an_uninterruptible_sleep_past_the_window_is_hung() {
        assert_eq!(classify(blocked(0, 121 * SEC), 120), Verdict::Hung);
    }

    #[test]
    fn the_same_sleep_inside_the_window_is_not_reported_yet() {
        assert_eq!(classify(blocked(0, 119 * SEC), 120), Verdict::Skip);
    }

    /// The boundary is inclusive: at exactly the timeout the task has gone the
    /// whole window without a switch, which is what the report claims.
    #[test]
    fn the_window_boundary_reports() {
        assert_eq!(classify(blocked(0, 120 * SEC), 120), Verdict::Hung);
    }

    #[test]
    fn a_switch_since_the_last_scan_is_progress_not_a_hang() {
        let mut o = blocked(0, 600 * SEC);
        o.switch_count = 8;
        assert_eq!(classify(o, 120), Verdict::Progressed);
    }

    /// A signal ends these, so a stuck one is the signal sender's problem, not
    /// evidence of a lost wakeup — the reference skips both.
    #[test]
    fn interruptible_and_killable_sleeps_are_skipped() {
        let mut o = blocked(0, 600 * SEC);
        o.wait = WaitState::Interruptible;
        assert_eq!(classify(o, 120), Verdict::Skip);
        o.wait = WaitState::Killable;
        assert_eq!(classify(o, 120), Verdict::Skip);
    }

    #[test]
    fn only_a_sleeping_task_is_a_candidate() {
        for st in [TaskState::Runnable, TaskState::Waking, TaskState::Zombie,
                   TaskState::Stopped] {
            let mut o = blocked(0, 600 * SEC);
            o.state = st;
            assert_eq!(classify(o, 120), Verdict::Skip, "state {st:?}");
        }
    }

    /// A task that has never been switched out has a meaningless zero
    /// timestamp; reporting it would name every freshly published waiter.
    #[test]
    fn a_task_that_never_switched_is_skipped() {
        let mut o = blocked(0, 600 * SEC);
        o.switch_count = 0;
        o.last_switch_count = 0;
        assert_eq!(classify(o, 120), Verdict::Skip);
    }

    #[test]
    fn a_zero_timeout_disables_the_detector() {
        assert_eq!(classify(blocked(0, 10_000 * SEC), 0), Verdict::Skip);
    }

    /// The window is measured from the LAST recorded switch, not from boot.
    #[test]
    fn the_window_runs_from_the_last_recorded_switch() {
        assert_eq!(classify(blocked(500 * SEC, 600 * SEC), 120), Verdict::Skip);
        assert_eq!(classify(blocked(500 * SEC, 621 * SEC), 120), Verdict::Hung);
    }

    #[test]
    fn the_report_budget_is_bounded_and_the_detect_count_is_not() {
        reset();
        for _ in 0..DEFAULT_WARNINGS { assert!(claim_report()); }
        assert!(!claim_report(), "budget must run out");
        assert!(!claim_report());
        assert_eq!(warnings_left(), 0);
        assert_eq!(detect_count(), u64::from(DEFAULT_WARNINGS) + 2,
                   "every hang counts even once reports are suppressed");
        reset();
    }
}
