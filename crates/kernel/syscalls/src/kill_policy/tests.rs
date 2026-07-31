use super::*;

const EPERM: i64 = -(Errno::Eperm.as_i32() as i64);
const ESRCH: i64 = -(Errno::Esrch.as_i32() as i64);
const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);

#[test]
fn the_pid_argument_selects_four_different_target_sets() {
    assert_eq!(classify(42), PidClass::Process(42));
    assert_eq!(classify(0), PidClass::CallerPgrp);
    assert_eq!(classify(-1), PidClass::Broadcast);
    assert_eq!(classify(-42), PidClass::Pgrp(42));
}

#[test]
fn int_min_is_not_a_process_group_because_negating_it_overflows() {
    assert_eq!(classify(i32::MIN), PidClass::NoSuchGroup);
    // The neighbouring value IS a group, so the exclusion is exactly one case.
    assert_eq!(classify(i32::MIN + 1), PidClass::Pgrp(i32::MAX as u32));
}

#[test]
fn an_empty_process_group_is_esrch() {
    assert_eq!(PgrpFold::new().finish(), ESRCH);
}

#[test]
fn one_permitted_member_makes_the_whole_group_send_succeed() {
    let mut f = PgrpFold::new();
    f.visit(EPERM);
    f.visit(0);
    f.visit(EPERM);
    assert_eq!(f.finish(), 0, "a later EPERM must not undo an earlier success");
}

#[test]
fn a_group_where_every_member_is_denied_reports_the_last_error() {
    let mut f = PgrpFold::new();
    f.visit(EPERM);
    f.visit(EINVAL);
    assert_eq!(f.finish(), EINVAL);
}

#[test]
fn a_broadcast_with_no_candidates_at_all_is_esrch() {
    assert_eq!(BroadcastFold::new().finish(), ESRCH);
}

#[test]
fn a_broadcast_swallows_eperm_but_still_counts_the_target() {
    // `kill(-1, SIGTERM)` from an unprivileged shell may be denied by every
    // single process and still returns 0 — the ESRCH-only-if-none rule counts
    // candidates, not successes. Treating a denied target as "not there" (the
    // prior behaviour) made killall5's shutdown sweep report ESRCH.
    let mut f = BroadcastFold::new();
    f.visit(EPERM);
    f.visit(EPERM);
    assert_eq!(f.finish(), 0);
}

#[test]
fn a_broadcast_reports_a_non_eperm_error_from_any_target() {
    let mut f = BroadcastFold::new();
    f.visit(0);
    f.visit(EINVAL);
    assert_eq!(f.finish(), EINVAL);
    // ...and a later success overwrites it, matching the last-writer rule.
    let mut g = BroadcastFold::new();
    g.visit(EINVAL);
    g.visit(0);
    assert_eq!(g.finish(), 0);
}

#[test]
fn signal_zero_is_valid_because_it_is_the_permission_probe() {
    assert!(signal_valid(0));
    assert!(signal_valid(1));
    assert!(signal_valid(64));
    assert!(!signal_valid(65));
    assert!(!signal_valid(-1));
}
