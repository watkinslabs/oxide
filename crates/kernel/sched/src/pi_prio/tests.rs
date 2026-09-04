use super::policy::*;
use crate::{SchedClass, SchedPolicy};

const fn rt(p: u8) -> SchedClass { SchedClass::Rt { prio: p, policy: SchedPolicy::Fifo } }
const fn rr(p: u8) -> SchedClass { SchedClass::Rt { prio: p, policy: SchedPolicy::Rr } }
const fn nt(level: u8) -> SchedClass { SchedClass::NtFixed { level, quantum: 3 } }
const fn fair(w: u32) -> SchedClass { SchedClass::Normal { weight: w } }

#[test]
fn an_rt_waiter_boosts_a_fair_owner() {
    assert_eq!(boost_class(fair(1024), &[rt(50)]), Some(rt(50)));
}

#[test]
fn a_fair_waiter_never_demotes_an_rt_owner() {
    assert_eq!(boost_class(rt(50), &[fair(1024)]), None);
}

#[test]
fn the_highest_of_several_waiters_wins() {
    assert_eq!(boost_class(fair(1024), &[rt(10), rt(80), fair(88), rt(30)]), Some(rt(80)));
}

#[test]
fn an_equal_priority_waiter_does_not_boost() {
    assert_eq!(boost_class(rt(50), &[rt(50), rt(20)]), None,
               "an equal-rank waiter needs no boost; a pointless requeue would send the owner to the tail of its own bucket");
}

#[test]
fn an_inherited_rr_priority_is_adopted_as_fifo() {
    assert_eq!(boost_class(fair(1024), &[rr(60)]), Some(rt(60)),
               "a boosted owner must not be preempted by an RR quantum expiry mid-critical-section");
}

#[test]
fn deadline_outranks_every_rt_priority() {
    assert_eq!(boost_class(rt(99), &[SchedClass::Deadline]), Some(SchedClass::Deadline));
    assert_eq!(boost_class(SchedClass::Deadline, &[rt(99)]), None);
}

#[test]
fn fair_nice_is_not_a_pi_waiter_key() {
    assert_eq!(boost_class(fair(15), &[fair(88761)]), None);
    assert_eq!(boost_class(fair(88761), &[fair(15)]), None);
}

#[test]
fn no_waiters_means_no_boost() {
    assert_eq!(boost_class(fair(1024), &[]), None);
    assert_eq!(boost_class(rt(9), &[]), None);
}

#[test]
fn every_non_rt_non_dl_waiter_has_one_default_key() {
    let fair_key = PiDonorKey { class: fair(1), deadline: 0, special: false };
    let idle_key = PiDonorKey { class: SchedClass::Idle, deadline: 0, special: false };
    assert!(!donor_key_outranks(fair_key, idle_key));
    assert!(!donor_key_outranks(idle_key, fair_key));
    assert_eq!(boost_class(SchedClass::Idle, &[fair(1)]), None);
    assert!(outranks(fair(1), SchedClass::Idle));
}

#[test]
fn nt_fixed_waiters_order_strictly_by_level() {
    let low = PiDonorKey { class: nt(5), deadline: 0, special: false };
    let high = PiDonorKey { class: nt(24), deadline: 0, special: false };
    let equal = PiDonorKey { class: nt(24), deadline: 0, special: false };
    assert!(donor_key_outranks(high, low));
    assert!(!donor_key_outranks(low, high));
    assert!(!donor_key_outranks(high, equal));
}

#[test]
fn nt_fixed_pi_rank_is_below_rt_and_above_fair() {
    let rt_key = PiDonorKey { class: rt(1), deadline: 0, special: false };
    let nt_key = PiDonorKey { class: nt(31), deadline: 0, special: false };
    let fair_key = PiDonorKey { class: fair(88_761), deadline: 0, special: false };
    assert!(donor_key_outranks(rt_key, nt_key));
    assert!(!donor_key_outranks(nt_key, rt_key));
    assert!(donor_key_outranks(nt_key, fair_key));
    assert!(!donor_key_outranks(fair_key, nt_key));
    assert!(outranks(nt(0), fair(88_761)));
    assert_eq!(boost_class(fair(1024), &[nt(5), nt(24)]), Some(nt(24)));
    assert_eq!(boost_class(nt(24), &[rt(1)]), Some(rt(1)));
}
