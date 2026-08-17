//! Whether an allocation fits: the decision a filesystem enforces.

use crate::quota::dqblk::Dqblk;
use crate::quota::limit::{self, Ask, Verdict};
use crate::quota::uapi::SPACE_UNIT;

const NOW: u64 = 1_000_000;
const GRACE: u64 = 604_800;

fn ask() -> Ask {
    Ask { now: NOW, grace: GRACE, exempt: false, enforced: true, allocating: true }
}

/// Soft at eight units, hard at ten, nothing used.
fn limits() -> Dqblk {
    Dqblk {
        bsoftlimit: 8 * SPACE_UNIT,
        bhardlimit: 10 * SPACE_UNIT,
        isoftlimit: 8,
        ihardlimit: 10,
        ..Dqblk::default()
    }
}

#[test]
fn a_limit_of_zero_is_unlimited_not_a_limit_of_nothing() {
    let d = Dqblk::default();
    assert_eq!(limit::space(&d, 1 << 40, &ask()), Verdict::Allow);
    assert_eq!(limit::inodes(&d, 1_000_000, &ask()), Verdict::Allow);
    // Zero on one axis only leaves the other enforced.
    let half = Dqblk { bhardlimit: SPACE_UNIT, ..Dqblk::default() };
    assert_eq!(limit::space(&half, SPACE_UNIT + 1, &ask()), Verdict::Deny);
    assert_eq!(limit::inodes(&half, 1_000_000, &ask()), Verdict::Allow);
}

#[test]
fn an_allocation_under_every_limit_fits() {
    let d = limits();
    assert_eq!(limit::space(&d, 4 * SPACE_UNIT, &ask()), Verdict::Allow);
    assert_eq!(limit::inodes(&d, 4, &ask()), Verdict::Allow);
}

#[test]
fn an_allocation_landing_exactly_on_a_limit_fits() {
    // The limits are inclusive: exceeding is what is refused.
    let d = limits();
    assert_eq!(limit::space(&d, 8 * SPACE_UNIT, &ask()), Verdict::Allow);
    assert_eq!(limit::inodes(&d, 8, &ask()), Verdict::Allow);
    let at_hard = Dqblk { bsoftlimit: 0, ..limits() };
    assert_eq!(limit::space(&at_hard, 10 * SPACE_UNIT, &ask()), Verdict::Allow);
}

#[test]
fn an_allocation_past_the_hard_limit_is_refused() {
    let d = limits();
    assert_eq!(limit::space(&d, 11 * SPACE_UNIT, &ask()), Verdict::Deny);
    assert_eq!(limit::inodes(&d, 11, &ask()), Verdict::Deny);
    // And past it by one byte, not just by one unit.
    assert_eq!(limit::space(&d, 10 * SPACE_UNIT + 1, &ask()), Verdict::Deny);
}

#[test]
fn crossing_the_soft_limit_the_first_time_is_allowed_and_starts_the_clock() {
    let d = limits();
    let v = limit::space(&d, 9 * SPACE_UNIT, &ask());
    assert_eq!(v, Verdict::AllowStartingGrace(NOW + GRACE));
    assert!(v.allowed(), "a soft limit permits the allocation that crosses it");
    let vi = limit::inodes(&d, 9, &ask());
    assert_eq!(vi, Verdict::AllowStartingGrace(NOW + GRACE));
}

#[test]
fn the_clock_the_first_crossing_starts_is_stored_in_the_record() {
    let mut d = limits();
    let v = limit::space(&d, 9 * SPACE_UNIT, &ask());
    assert!(limit::apply_space(&mut d, 9 * SPACE_UNIT, v));
    assert_eq!(d.btime, NOW + GRACE);
    assert_eq!(d.curspace, 9 * SPACE_UNIT);
    let mut e = limits();
    let vi = limit::inodes(&e, 9, &ask());
    assert!(limit::apply_inodes(&mut e, 9, vi));
    assert_eq!(e.itime, NOW + GRACE);
    assert_eq!(e.curinodes, 9);
}

#[test]
fn over_the_soft_limit_within_the_grace_still_fits() {
    let d = Dqblk { curspace: 9 * SPACE_UNIT, btime: NOW + 10, ..limits() };
    assert_eq!(limit::space(&d, 0, &ask()), Verdict::Allow);
    let e = Dqblk { curinodes: 9, itime: NOW + 10, ..limits() };
    assert_eq!(limit::inodes(&e, 0, &ask()), Verdict::Allow);
}

#[test]
fn over_the_soft_limit_past_the_grace_is_refused() {
    let d = Dqblk { curspace: 9 * SPACE_UNIT, btime: NOW - 1, ..limits() };
    assert_eq!(limit::space(&d, 0, &ask()), Verdict::Deny);
    // Expiring exactly now is expired.
    let at = Dqblk { btime: NOW, ..d };
    assert_eq!(limit::space(&at, 0, &ask()), Verdict::Deny);
    let e = Dqblk { curinodes: 9, itime: NOW - 1, ..limits() };
    assert_eq!(limit::inodes(&e, 0, &ask()), Verdict::Deny);
}

#[test]
fn an_expired_grace_does_not_refuse_an_identity_back_under_its_soft_limit() {
    // The clock is only consulted while the soft limit is exceeded.
    let d = Dqblk { curspace: 2 * SPACE_UNIT, btime: NOW - 1, ..limits() };
    assert_eq!(limit::space(&d, SPACE_UNIT, &ask()), Verdict::Allow);
}

#[test]
fn giving_space_back_under_the_soft_limit_stops_the_clock() {
    let mut d = Dqblk { curspace: 9 * SPACE_UNIT, btime: NOW + GRACE, ..limits() };
    limit::free_space(&mut d, SPACE_UNIT);
    assert_eq!(d.curspace, 8 * SPACE_UNIT);
    assert_eq!(d.btime, 0, "a grace left running refuses a later allocation");
    let mut e = Dqblk { curinodes: 9, itime: NOW + GRACE, ..limits() };
    limit::free_inodes(&mut e, 1);
    assert_eq!(e.curinodes, 8);
    assert_eq!(e.itime, 0);
}

#[test]
fn giving_back_while_still_over_the_soft_limit_leaves_the_clock_running() {
    let mut d = Dqblk { curspace: 10 * SPACE_UNIT, btime: NOW + GRACE, ..limits() };
    limit::free_space(&mut d, SPACE_UNIT);
    assert_eq!(d.curspace, 9 * SPACE_UNIT);
    assert_eq!(d.btime, NOW + GRACE);
}

#[test]
fn the_privileged_caller_passes_a_hard_limit() {
    let d = limits();
    let exempt = Ask { exempt: true, ..ask() };
    assert_eq!(limit::space(&d, 100 * SPACE_UNIT, &exempt), Verdict::AllowStartingGrace(NOW + GRACE));
    assert_eq!(limit::inodes(&d, 100, &exempt), Verdict::AllowStartingGrace(NOW + GRACE));
    // And past an expired grace.
    let over = Dqblk { curspace: 9 * SPACE_UNIT, btime: NOW - 1, ..limits() };
    assert_eq!(limit::space(&over, 0, &exempt), Verdict::Allow);
}

#[test]
fn the_privileged_caller_still_starts_the_clock_for_everyone_else() {
    let mut d = limits();
    let exempt = Ask { exempt: true, ..ask() };
    let v = limit::space(&d, 9 * SPACE_UNIT, &exempt);
    limit::apply_space(&mut d, 9 * SPACE_UNIT, v);
    assert_eq!(d.btime, NOW + GRACE);
    // The next unprivileged allocation is measured against that clock.
    let later = Ask { now: NOW + GRACE + 1, ..ask() };
    assert_eq!(limit::space(&d, 0, &later), Verdict::Deny);
}

#[test]
fn a_mount_that_only_tracks_refuses_nothing() {
    let d = limits();
    let tracking = Ask { enforced: false, ..ask() };
    assert_eq!(limit::space(&d, 1 << 40, &tracking), Verdict::Allow);
    assert_eq!(limit::inodes(&d, 1_000_000, &tracking), Verdict::Allow);
}

#[test]
fn tracking_still_accounts_what_it_does_not_refuse() {
    let mut d = limits();
    let tracking = Ask { enforced: false, ..ask() };
    let v = limit::space(&d, 40 * SPACE_UNIT, &tracking);
    limit::apply_space(&mut d, 40 * SPACE_UNIT, v);
    assert_eq!(d.curspace, 40 * SPACE_UNIT, "a tracking mount still counts");
    assert_eq!(d.btime, 0, "and starts no clock it will never enforce");
}

#[test]
fn a_reservation_may_not_take_grace_that_has_not_started() {
    let d = limits();
    let reserving = Ask { allocating: false, ..ask() };
    assert_eq!(limit::space(&d, 9 * SPACE_UNIT, &reserving), Verdict::Deny);
    // Under the soft limit a reservation is as good as an allocation.
    assert_eq!(limit::space(&d, 8 * SPACE_UNIT, &reserving), Verdict::Allow);
    // And a grace already running covers it.
    let running = Dqblk { curspace: 9 * SPACE_UNIT, btime: NOW + 10, ..limits() };
    assert_eq!(limit::space(&running, 0, &reserving), Verdict::Allow);
}

#[test]
fn a_denied_allocation_changes_nothing() {
    let mut d = limits();
    let v = limit::space(&d, 11 * SPACE_UNIT, &ask());
    assert!(!limit::apply_space(&mut d, 11 * SPACE_UNIT, v));
    assert_eq!(d.curspace, 0);
    assert_eq!(d.btime, 0);
}

#[test]
fn what_statfs_reports_is_the_narrower_of_the_two_limits() {
    assert_eq!(limit::effective_limit(0, 0), None);
    assert_eq!(limit::effective_limit(10, 0), Some(10));
    assert_eq!(limit::effective_limit(0, 8), Some(8));
    assert_eq!(limit::effective_limit(10, 8), Some(8));
    assert_eq!(limit::effective_limit(8, 10), Some(8));
    let d = Dqblk { curspace: 3 * SPACE_UNIT, curinodes: 3, ..limits() };
    assert_eq!(limit::space_remaining(&d), Some(5 * SPACE_UNIT));
    assert_eq!(limit::inodes_remaining(&d), Some(5));
    assert_eq!(limit::space_remaining(&Dqblk::default()), None);
    assert_eq!(limit::inodes_remaining(&Dqblk::default()), None);
    // An identity already past its limit has nothing left, not a negative.
    let over = Dqblk { curspace: 99 * SPACE_UNIT, ..limits() };
    assert_eq!(limit::space_remaining(&over), Some(0));
}
