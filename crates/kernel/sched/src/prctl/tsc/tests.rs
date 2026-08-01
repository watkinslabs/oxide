// `prctl(PR_SET_TSC)` contract. The privileged register write is a host no-op
// here, so these pin the DECISION half: the value↔flag mapping, the
// round-trip, and the switch-time re-assert rule.

use super::*;
use crate::task::SchedClass;

fn task(tid: u32) -> Task {
    Task::new(tid, "tsc", SchedClass::Normal { weight: 1024 })
}

#[test]
fn sigsegv_arms_and_enable_disarms() {
    assert_eq!(mode_to_flag(PR_TSC_SIGSEGV), Ok(true));
    assert_eq!(mode_to_flag(PR_TSC_ENABLE), Ok(false));
}

/// Linux `set_tsc_mode` has an explicit `else return -EINVAL`; 0 and 3 are
/// not "close enough to enable".
#[test]
fn every_other_mode_value_is_einval() {
    for v in [0u32, 3, 4, 0xffff_ffff] {
        assert_eq!(mode_to_flag(v), Err(Errno::Einval), "mode {v}");
    }
}

/// `PR_GET_TSC` reports what `PR_SET_TSC` installed, not a hard-coded
/// `PR_TSC_ENABLE`. A sandbox that reads back ENABLE after arming SIGSEGV
/// believes its counter is still readable and skips its own mitigation.
#[test]
fn get_reports_the_mode_set() {
    let t = task(1);
    assert_eq!(flag_to_mode(denied(&t)), PR_TSC_ENABLE);
    apply(&t, true);
    assert!(denied(&t));
    assert_eq!(flag_to_mode(denied(&t)), PR_TSC_SIGSEGV);
    apply(&t, false);
    assert!(!denied(&t));
    assert_eq!(flag_to_mode(denied(&t)), PR_TSC_ENABLE);
}

/// A fresh task may read the counter — Linux clears `TIF_NOTSC` in a new
/// thread_info and every process starts able to `rdtsc`.
#[test]
fn a_new_task_may_read_the_counter() {
    assert!(!denied(&task(2)));
}

/// The switch-time re-assert is edge-triggered (`(tifp ^ tifn) & _TIF_NOTSC`):
/// an unchanged mode must not put a serialising control-register write on
/// every context switch.
#[test]
fn switch_between_equal_modes_writes_nothing() {
    switch_to(false, false);
    switch_to(true, true);
    // No observable state on the host; the contract is that neither call
    // panics and both take the early return. The transitions below are the
    // ones that must reach the register.
    switch_to(false, true);
    switch_to(true, false);
}

/// The two modes are distinct values, and neither is zero — `PR_GET_TSC`
/// writes them through a user pointer, where a zero would be indistinguishable
/// from an untouched buffer.
#[test]
fn mode_values_match_the_uapi() {
    assert_eq!(PR_TSC_ENABLE, 1);
    assert_eq!(PR_TSC_SIGSEGV, 2);
}
