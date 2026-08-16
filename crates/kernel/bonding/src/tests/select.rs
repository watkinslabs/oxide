// Active-slave selection and the peer-notification gate.

extern crate alloc;
use alloc::vec;

use crate::select::{
    choose_primary_or_current, find_best_slave, highest_prio_up, should_notify_peers,
    SelectContext,
};
use crate::slave::{LinkState, SlaveRole, SlaveState};
use crate::uapi::{
    BOND_MODE_8023AD, BOND_MODE_ACTIVEBACKUP, BOND_PRI_RESELECT_ALWAYS,
    BOND_PRI_RESELECT_BETTER, BOND_PRI_RESELECT_FAILURE, DUPLEX_FULL, DUPLEX_HALF,
};

fn s(link: LinkState, speed: u32, duplex: u8, prio: i32) -> SlaveState {
    SlaveState { link, carrier: link == LinkState::Up, role: SlaveRole::Active,
                 speed_mbps: speed, duplex, prio, ..SlaveState::default() }
}

fn up(speed: u32) -> SlaveState { s(LinkState::Up, speed, DUPLEX_FULL, 0) }
fn down() -> SlaveState { s(LinkState::Down, 0, DUPLEX_HALF, 0) }

#[test]
fn always_switches_to_the_primary_the_moment_it_is_up() {
    let sl = vec![up(1000), up(10000)];
    let ctx = SelectContext { primary: Some(0), curr_active: Some(1),
                              primary_reselect: BOND_PRI_RESELECT_ALWAYS,
                              ..SelectContext::default() };
    assert_eq!(choose_primary_or_current(&sl, &ctx), Some(0));
}

#[test]
fn failure_keeps_the_current_slave_while_it_is_up() {
    let sl = vec![up(10000), up(1000)];
    let ctx = SelectContext { primary: Some(0), curr_active: Some(1),
                              primary_reselect: BOND_PRI_RESELECT_FAILURE,
                              ..SelectContext::default() };
    assert_eq!(choose_primary_or_current(&sl, &ctx), Some(1));
}

#[test]
fn failure_falls_back_to_the_primary_once_the_current_slave_goes_down() {
    let sl = vec![up(1000), down()];
    let ctx = SelectContext { primary: Some(0), curr_active: Some(1),
                              primary_reselect: BOND_PRI_RESELECT_FAILURE,
                              ..SelectContext::default() };
    assert_eq!(choose_primary_or_current(&sl, &ctx), Some(0));
}

#[test]
fn better_switches_only_when_the_primary_is_at_least_as_fast() {
    let ctx = |p: usize, c: usize| SelectContext {
        primary: Some(p), curr_active: Some(c),
        primary_reselect: BOND_PRI_RESELECT_BETTER, ..SelectContext::default()
    };
    // Slower primary loses.
    let slow = vec![up(1000), up(10000)];
    assert_eq!(choose_primary_or_current(&slow, &ctx(0, 1)), Some(1));
    // Faster primary wins.
    let fast = vec![up(10000), up(1000)];
    assert_eq!(choose_primary_or_current(&fast, &ctx(0, 1)), Some(0));
}

#[test]
fn better_breaks_an_equal_speed_tie_on_duplex() {
    let ctx = SelectContext { primary: Some(0), curr_active: Some(1),
                              primary_reselect: BOND_PRI_RESELECT_BETTER,
                              ..SelectContext::default() };
    // Equal speed, primary half duplex against a full-duplex current: keep current.
    let worse = vec![s(LinkState::Up, 1000, DUPLEX_HALF, 0),
                     s(LinkState::Up, 1000, DUPLEX_FULL, 0)];
    assert_eq!(choose_primary_or_current(&worse, &ctx), Some(1));
    // Equal speed and equal duplex is not an improvement either.
    let equal = vec![s(LinkState::Up, 1000, DUPLEX_FULL, 0),
                     s(LinkState::Up, 1000, DUPLEX_FULL, 0)];
    assert_eq!(choose_primary_or_current(&equal, &ctx), Some(1));
    // Full-duplex primary against a half-duplex current wins.
    let better = vec![s(LinkState::Up, 1000, DUPLEX_FULL, 0),
                      s(LinkState::Up, 1000, DUPLEX_HALF, 0)];
    assert_eq!(choose_primary_or_current(&better, &ctx), Some(0));
}

#[test]
fn a_forced_primary_wins_once_regardless_of_the_policy() {
    let sl = vec![up(1000), up(10000)];
    let ctx = SelectContext { primary: Some(0), curr_active: Some(1), force_primary: true,
                              primary_reselect: BOND_PRI_RESELECT_FAILURE,
                              ..SelectContext::default() };
    assert_eq!(choose_primary_or_current(&sl, &ctx), Some(0));
}

#[test]
fn a_down_primary_yields_to_the_highest_priority_up_slave() {
    let mut sl = vec![down(), up(1000), up(1000)];
    sl[2].prio = 5;
    assert_eq!(highest_prio_up(&sl), Some(2));
    let ctx = SelectContext { primary: Some(0), curr_active: Some(1),
                              primary_reselect: BOND_PRI_RESELECT_FAILURE,
                              ..SelectContext::default() };
    // The higher-priority slave becomes the candidate, and the failure policy
    // then keeps the up current slave.
    assert_eq!(choose_primary_or_current(&sl, &ctx), Some(1));
}

#[test]
fn with_no_primary_and_no_up_slave_nothing_is_selected() {
    let sl = vec![down(), down()];
    let ctx = SelectContext { curr_active: Some(0), ..SelectContext::default() };
    assert_eq!(choose_primary_or_current(&sl, &ctx), None);
}

#[test]
fn the_current_slave_is_kept_when_it_is_the_only_up_one() {
    let sl = vec![down(), up(1000)];
    let ctx = SelectContext { curr_active: Some(1), ..SelectContext::default() };
    assert_eq!(choose_primary_or_current(&sl, &ctx), Some(1));
}

#[test]
fn the_best_slave_falls_back_to_the_recovering_one_closest_to_finishing() {
    let mut sl = vec![down(), down()];
    sl[0].link = LinkState::Back; sl[0].carrier = true; sl[0].delay = 7;
    sl[1].link = LinkState::Back; sl[1].carrier = true; sl[1].delay = 2;
    let ctx = SelectContext { updelay: 10, ..SelectContext::default() };
    assert_eq!(find_best_slave(&sl, &ctx), Some(1));
}

#[test]
fn the_best_slave_prefers_any_settled_up_slave_over_a_recovering_one() {
    let mut sl = vec![down(), up(1000)];
    sl[0].link = LinkState::Back; sl[0].carrier = true; sl[0].delay = 0;
    let ctx = SelectContext { updelay: 10, ..SelectContext::default() };
    assert_eq!(find_best_slave(&sl, &ctx), Some(1));
}

#[test]
fn a_notification_is_owed_only_when_the_delay_divides_the_remaining_count() {
    // No delay configured: every remaining notification is due.
    assert!(should_notify_peers(3, 0, true, BOND_MODE_ACTIVEBACKUP, 1, Some(0), false));
    // A delay of four: only counts divisible by four are due.
    assert!(!should_notify_peers(3, 4, true, BOND_MODE_ACTIVEBACKUP, 1, Some(0), false));
    assert!(should_notify_peers(4, 4, true, BOND_MODE_ACTIVEBACKUP, 1, Some(0), false));
}

#[test]
fn nothing_is_notified_with_no_debt_no_carrier_or_no_path() {
    assert!(!should_notify_peers(0, 0, true, BOND_MODE_ACTIVEBACKUP, 1, Some(0), false));
    assert!(!should_notify_peers(1, 0, false, BOND_MODE_ACTIVEBACKUP, 1, Some(0), false));
    assert!(!should_notify_peers(1, 0, true, BOND_MODE_ACTIVEBACKUP, 1, None, false));
    assert!(!should_notify_peers(1, 0, true, BOND_MODE_ACTIVEBACKUP, 1, Some(0), true));
    assert!(!should_notify_peers(1, 0, true, BOND_MODE_8023AD, 0, Some(0), false));
    assert!(should_notify_peers(1, 0, true, BOND_MODE_8023AD, 2, None, true));
}
