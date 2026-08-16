//! When a mount turns age-threshold cleaning on, and when it turns it on late.
//!
//! The two decisions are deliberately measured against different thresholds —
//! the format's at mount, the tuned one afterwards — and that is exactly the
//! difference a test has to pin, because both read as "is the volume old
//! enough" and only one of them can be changed from userspace.

use super::*;

const WEEK: u64 = 60 * 60 * 24 * 7;

#[test]
fn a_mount_that_did_not_ask_for_it_does_not_get_it() {
    let mut a = Atgc::new();
    a.enable_at_mount(false, 100 * WEEK);
    assert!(!a.enabled);
}

#[test]
fn a_volume_younger_than_the_format_threshold_does_not_get_it() {
    let mut a = Atgc::new();
    a.enable_at_mount(true, WEEK - 1);
    assert!(!a.enabled, "no section could have aged a week on a volume this young");
    let mut b = Atgc::new();
    b.enable_at_mount(true, WEEK);
    assert!(b.enabled, "at the threshold it is old enough");
}

#[test]
fn the_mount_decision_ignores_a_tuned_threshold() {
    let mut a = Atgc::new();
    a.age_threshold = 1;
    a.enable_at_mount(true, 2);
    assert!(!a.enabled, "at mount the bound is the format's, not the tuned one");
}

#[test]
fn a_volume_that_has_aged_into_it_may_turn_it_on_late() {
    let a = Atgc::new();
    assert!(!a.may_reinit(true, WEEK - 1), "still too young");
    assert!(a.may_reinit(true, WEEK), "old enough now");
    assert!(!a.may_reinit(false, 100 * WEEK), "and only if the mount asked");
}

#[test]
fn turning_it_on_late_respects_a_lowered_threshold() {
    let mut a = Atgc::new();
    assert!(!a.may_reinit(true, 60), "a minute is not a week");
    a.age_threshold = 60;
    assert!(a.may_reinit(true, 60), "a minute is a minute");
}

#[test]
fn a_mount_that_already_has_it_does_not_turn_it_on_again() {
    let mut a = Atgc::new();
    a.enable_at_mount(true, 100 * WEEK);
    assert!(a.enabled);
    assert!(!a.may_reinit(true, 100 * WEEK));
}
