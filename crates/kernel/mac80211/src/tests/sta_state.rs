// The station state ladder and the table that walks it.

use crate::ops::StaState;
use crate::sta_info::{state, Sta, StaTable};
use crate::tests_fixture as f;

const LADDER: [StaState; 5] = [StaState::NotExist, StaState::None, StaState::Auth,
                               StaState::Assoc, StaState::Authorized];

#[test]
fn the_ladder_is_ordered_and_has_two_ends() {
    for w in LADDER.windows(2) { assert!(w[0] < w[1]); }
    assert_eq!(state::down(StaState::NotExist), None);
    assert_eq!(state::up(StaState::Authorized), None);
}

#[test]
fn every_neighbouring_pair_is_a_single_step_and_nothing_else_is() {
    for (i, &from) in LADDER.iter().enumerate() {
        for (j, &to) in LADDER.iter().enumerate() {
            let neighbour = i.abs_diff(j) == 1;
            assert_eq!(state::is_single_step(from, to), neighbour,
                       "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn a_multi_step_move_is_walked_one_step_at_a_time() {
    let steps: alloc::vec::Vec<_> =
        state::steps(StaState::NotExist, StaState::Authorized).collect();
    assert_eq!(steps.len(), 4);
    for (from, to) in steps.iter() { assert!(state::is_single_step(*from, *to)); }
    assert_eq!(steps[0].0, StaState::NotExist);
    assert_eq!(steps[3].1, StaState::Authorized);
    // Downward too.
    let down: alloc::vec::Vec<_> =
        state::steps(StaState::Authorized, StaState::None).collect();
    assert_eq!(down.len(), 3);
    assert_eq!(down[2].1, StaState::None);
    // And nowhere is no steps.
    assert_eq!(state::steps(StaState::Auth, StaState::Auth).count(), 0);
}

#[test]
fn only_the_top_step_carries_data() {
    for s in LADDER {
        assert_eq!(state::data_allowed(s), s == StaState::Authorized, "{s:?}");
    }
}

#[test]
fn association_and_key_installation_have_their_own_thresholds() {
    assert!(!state::is_associated(StaState::Auth));
    assert!(state::is_associated(StaState::Assoc));
    assert!(state::is_associated(StaState::Authorized));
    assert!(!state::keys_allowed(StaState::None));
    assert!(state::keys_allowed(StaState::Auth));
}

#[test]
fn the_table_reports_a_missing_station_as_not_existing() {
    let t = StaTable::default();
    assert_eq!(t.state(f::PEER), StaState::NotExist);
    assert!(!t.contains(f::PEER));
    assert!(t.is_empty());
}

#[test]
fn a_second_insertion_does_not_replace_the_first() {
    // Replacing would discard the reorder windows and replay counters of a
    // link that is still up.
    let t = StaTable::default();
    let mut first = Sta::new(f::PEER, 0);
    first.aid = 7;
    assert!(t.insert(first));
    assert!(!t.insert(Sta::new(f::PEER, 0)));
    assert_eq!(t.with(f::PEER, |s| s.aid), Some(7));
    assert_eq!(t.len(), 1);
}

#[test]
fn a_move_up_the_ladder_invokes_every_step_in_order() {
    let t = StaTable::default();
    t.insert(Sta::new(f::PEER, 0));
    let seen = core::cell::RefCell::new(alloc::vec::Vec::new());
    assert!(t.set_state(f::PEER, StaState::Authorized, |from, to| {
        seen.borrow_mut().push((from, to));
        true
    }));
    assert_eq!(seen.borrow().len(), 3);
    assert_eq!(t.state(f::PEER), StaState::Authorized);
}

#[test]
fn a_refused_step_leaves_the_station_where_the_driver_agreed_it_was() {
    let t = StaTable::default();
    t.insert(Sta::new(f::PEER, 0));
    let calls = core::cell::Cell::new(0);
    assert!(!t.set_state(f::PEER, StaState::Authorized, |_, to| {
        calls.set(calls.get() + 1);
        to != StaState::Assoc
    }));
    assert_eq!(t.state(f::PEER), StaState::Auth, "the refused step did not happen");
}

#[test]
fn a_station_that_is_not_there_cannot_be_moved() {
    let t = StaTable::default();
    assert!(!t.set_state(f::PEER, StaState::Auth, |_, _| true));
}

#[test]
fn association_identifiers_are_handed_out_lowest_first_and_never_zero() {
    let t = StaTable::default();
    assert_eq!(t.next_aid(), Some(1));
    let mut a = Sta::new(f::PEER, 0);
    a.aid = 1;
    t.insert(a);
    assert_eq!(t.next_aid(), Some(2));
    let mut b = Sta::new(f::OTHER, 0);
    b.aid = 2;
    t.insert(b);
    assert_eq!(t.next_aid(), Some(3));
}

#[test]
fn the_duplicate_check_covers_the_fragment_number_too() {
    // Two fragments of one frame share a sequence number and differ only in
    // the fragment number; comparing only the sequence number would discard
    // every fragment after the first.
    let mut sta = Sta::new(f::PEER, 0);
    let seq = |sn: u16, frag: u16| wireless::ieee80211::fctl::sn_to_seq(sn, frag);
    assert!(!sta.is_duplicate(None, seq(10, 0), false));
    assert!(!sta.is_duplicate(None, seq(10, 1), true), "a different fragment is not a copy");
    assert!(sta.is_duplicate(None, seq(10, 1), true), "the same fragment retried is");
}

#[test]
fn a_frame_not_marked_as_a_retry_is_never_a_duplicate() {
    let mut sta = Sta::new(f::PEER, 0);
    let seq = wireless::ieee80211::fctl::sn_to_seq(4, 0);
    assert!(!sta.is_duplicate(None, seq, false));
    assert!(!sta.is_duplicate(None, seq, false), "the peer reused the value, legitimately");
}

#[test]
fn duplicate_history_is_kept_per_traffic_identifier() {
    let mut sta = Sta::new(f::PEER, 0);
    let seq = wireless::ieee80211::fctl::sn_to_seq(1, 0);
    assert!(!sta.is_duplicate(Some(0), seq, true));
    assert!(!sta.is_duplicate(Some(6), seq, true), "another identifier has its own history");
    assert!(sta.is_duplicate(Some(0), seq, true));
}

#[test]
fn transmit_sequence_counters_are_per_identifier() {
    let mut sta = Sta::new(f::PEER, 0);
    assert_eq!(sta.next_seq(Some(0)), 0);
    assert_eq!(sta.next_seq(Some(0)), 1);
    assert_eq!(sta.next_seq(Some(6)), 0, "a fresh identifier starts from zero");
    assert_eq!(sta.next_seq(None), 0, "and so does the non-QoS stream");
    assert_eq!(sta.next_seq(Some(0)), 2);
}

#[test]
fn an_inactive_station_is_reported_only_after_the_whole_timeout() {
    let sta = Sta::new(f::PEER, 1_000);
    assert!(!sta.is_inactive(1_000 + crate::limits::STA_INACTIVITY_NS - 1));
    assert!(sta.is_inactive(1_000 + crate::limits::STA_INACTIVITY_NS));
}

#[test]
fn a_flush_empties_the_table_and_reports_who_was_in_it() {
    let t = StaTable::default();
    t.insert(Sta::new(f::PEER, 0));
    t.insert(Sta::new(f::OTHER, 0));
    let gone = t.flush();
    assert_eq!(gone.len(), 2);
    assert!(t.is_empty());
}
