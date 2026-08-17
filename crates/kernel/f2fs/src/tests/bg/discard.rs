//! The discard policy and the pending lists it issues from.
//!
//! The behaviour worth pinning is the behaviour a device notices: how many
//! runs go per round, in what order, which are held back at what granularity,
//! and what happens to the interval afterwards. None of it needs a device.

use super::*;
use crate::opts::DiscardUnit;

fn dcc() -> DiscardControl { DiscardControl::new(DiscardUnit::Block, 1) }

fn bg_policy(d: &DiscardControl) -> DiscardPolicy {
    d.init_policy(DiscardType::Bg, d.granularity, 0)
}

#[test]
fn the_defaults_are_the_ones_the_format_states() {
    let d = dcc();
    assert_eq!(d.granularity, 16);
    assert_eq!(d.max_ordered_discard, 16);
    assert_eq!(d.max_discard_request, 8);
    assert_eq!(d.min_issue_time, 50);
    assert_eq!(d.mid_issue_time, 500);
    assert_eq!(d.max_issue_time, 60_000);
    assert_eq!(d.urgent_util, 80);
    assert_eq!(d.io_aware, IoAware::Enable);
    assert_eq!(d.io_aware_gran, 512);
}

#[test]
fn a_mount_that_announces_whole_segments_starts_at_that_granularity() {
    // A run shorter than a segment can never be announced under that unit, so
    // the thread must not spend a round finding that out.
    let d = DiscardControl::new(DiscardUnit::Segment, 1);
    assert_eq!(d.granularity, crate::uapi::BLKS_PER_SEG);
    let d = DiscardControl::new(DiscardUnit::Section, 4);
    assert_eq!(d.granularity, crate::uapi::BLKS_PER_SEG * 4);
}

#[test]
fn a_run_waits_in_the_list_for_its_length() {
    use crate::bg::discard::{plist_idx, MAX_PLIST_NUM};
    assert_eq!(plist_idx(1), 0);
    assert_eq!(plist_idx(16), 15);
    assert_eq!(plist_idx(MAX_PLIST_NUM as u32), MAX_PLIST_NUM - 1);
    assert_eq!(plist_idx(100_000), MAX_PLIST_NUM - 1, "longer than any list is the last");
}

#[test]
fn parked_runs_are_counted_in_runs_and_in_blocks() {
    let mut d = dcc();
    d.extend([(100, 4), (200, 32)]);
    assert_eq!(d.cmd_count(), 2);
    assert_eq!(d.undiscard_blks(), 36);
}

#[test]
fn a_zero_length_run_is_not_a_run() {
    let mut d = dcc();
    d.add((100, 0));
    assert_eq!(d.cmd_count(), 0);
}

#[test]
fn the_background_policy_yields_and_orders_and_the_forced_one_does_neither() {
    let d = dcc();
    let bg = d.init_policy(DiscardType::Bg, d.granularity, 0);
    assert!(bg.io_aware);
    assert!(bg.ordered);
    let force = d.init_policy(DiscardType::Force, 1, 0);
    assert!(!force.io_aware);
    assert!(!force.ordered);
}

#[test]
fn a_nearly_full_volume_announces_every_run_and_stops_waiting_between_rounds() {
    let mut d = dcc();
    d.extend([(100, 1)]);
    let p = d.init_policy(DiscardType::Bg, d.granularity, 81);
    assert_eq!(p.granularity, 1, "past the threshold, length stops mattering");
    assert_eq!(p.max_interval, d.min_issue_time, "and the long interval collapses");
}

#[test]
fn a_nearly_full_volume_with_nothing_parked_keeps_its_long_interval() {
    let d = dcc();
    let p = d.init_policy(DiscardType::Bg, d.granularity, 81);
    assert_eq!(p.granularity, 1);
    assert_eq!(p.max_interval, d.max_issue_time, "there is nothing to hurry for");
}

#[test]
fn the_unmount_policy_takes_everything_however_short() {
    // The checkpoint written after it says the volume is trimmed. That claim
    // has to be true of every run.
    let d = dcc();
    let p = d.init_policy(DiscardType::Umount, 1, 0);
    assert_eq!(p.granularity, 1);
    assert!(p.timeout);
    assert!(!p.io_aware);
}

#[test]
fn a_round_issues_no_more_than_it_is_allowed_to() {
    let mut d = dcc();
    for i in 0..20u32 { d.add((1000 + i * 40, 32)); }
    let p = d.init_policy(DiscardType::Force, 16, 0);
    let round = d.issue_round(&p, true);
    assert_eq!(round.issued(), 8, "the round yields after its allowance");
    assert_eq!(d.cmd_count(), 12, "and the rest stay parked");
}

#[test]
fn runs_below_the_granularity_are_left_alone() {
    let mut d = dcc();
    d.extend([(100, 4), (200, 8), (300, 32)]);
    let p = d.init_policy(DiscardType::Force, 16, 0);
    let round = d.issue_round(&p, true);
    assert_eq!(round.runs, alloc::vec![(300, 32)]);
    assert_eq!(d.cmd_count(), 2, "the short ones wait for a policy that wants them");
}

#[test]
fn the_length_first_pass_takes_the_longest_runs_first() {
    let mut d = dcc();
    d.extend([(100, 20), (200, 400), (300, 64)]);
    let p = d.init_policy(DiscardType::Force, 20, 0);
    let round = d.issue_round(&p, true);
    assert_eq!(round.runs, alloc::vec![(200, 400), (300, 64), (100, 20)]);
}

#[test]
fn the_ordered_pass_sweeps_by_address_and_resumes_where_it_stopped() {
    let mut d = dcc();
    d.max_discard_request = 2;
    d.extend([(500, 4), (100, 4), (300, 4), (700, 4)]);
    let p = d.init_policy(DiscardType::Bg, 1, 0);
    assert!(p.ordered);
    let first = d.issue_round(&p, true);
    assert_eq!(first.runs, alloc::vec![(100, 4), (300, 4)]);
    let second = d.issue_round(&p, true);
    assert_eq!(second.runs, alloc::vec![(500, 4), (700, 4)], "and does not start over");
}

#[test]
fn a_sweep_that_reached_the_end_starts_over() {
    let mut d = dcc();
    d.extend([(500, 4)]);
    let p = d.init_policy(DiscardType::Bg, 1, 0);
    d.issue_round(&p, true);
    assert_eq!(d.next_pos, 0, "or the runs below where it stopped are never reached");
}

#[test]
fn the_ordered_pass_is_not_used_for_runs_longer_than_it_covers() {
    let mut d = dcc();
    d.extend([(500, 64), (100, 64)]);
    let p = d.init_policy(DiscardType::Bg, 64, 0);
    let round = d.issue_round(&p, true);
    assert_eq!(round.runs.len(), 2);
    assert_eq!(d.next_pos, 0, "the length-first pass does not move the sweep");
}

#[test]
fn a_busy_device_stops_a_round_that_is_allowed_to_yield() {
    let mut d = dcc();
    d.extend([(100, 4)]);
    let p = d.init_policy(DiscardType::Bg, 1, 0);
    let round = d.issue_round(&p, false);
    assert_eq!(round.issued(), 0);
    assert!(round.io_interrupted);
    assert_eq!(d.cmd_count(), 1, "nothing was taken");
}

#[test]
fn a_busy_device_does_not_stop_a_round_that_is_not_allowed_to_yield() {
    let mut d = dcc();
    d.extend([(100, 32)]);
    let p = d.init_policy(DiscardType::Force, 16, 0);
    let round = d.issue_round(&p, false);
    assert_eq!(round.issued(), 1);
    assert!(!round.io_interrupted);
}

#[test]
fn a_run_long_enough_goes_whatever_the_device_is_doing() {
    // The yielding threshold is a LENGTH: a long run is worth the stall,
    // which is the whole reason the lists are kept by length.
    let mut d = dcc();
    d.io_aware_gran = 16;
    d.extend([(100, 400)]);
    let p = d.init_policy(DiscardType::Bg, 400, 0);
    let round = d.issue_round(&p, false);
    assert_eq!(round.issued(), 1);
}

#[test]
fn a_round_that_issued_something_and_left_more_looks_again_soon() {
    let mut d = dcc();
    d.max_discard_request = 1;
    d.extend([(100, 32), (200, 32)]);
    let p = bg_policy(&d);
    let round = d.issue_round(&p, true);
    assert_eq!(round.issued(), 1);
    assert_eq!(d.next_wait(&p, &round), p.min_interval, "there is more to hand over");
}

#[test]
fn a_round_that_found_nothing_sleeps_long() {
    let mut d = dcc();
    let p = bg_policy(&d);
    let round = d.issue_round(&p, true);
    assert_eq!(d.next_wait(&p, &round), p.max_interval);
}

#[test]
fn a_round_the_device_was_too_busy_for_waits_the_middle_interval() {
    let mut d = dcc();
    d.extend([(100, 4), (200, 4)]);
    let p = d.init_policy(DiscardType::Bg, 1, 0);
    let round = d.issue_round(&p, false);
    assert!(round.io_interrupted);
    assert_eq!(d.next_wait(&p, &round), p.mid_interval,
               "busy is not the same answer as empty");
}

#[test]
fn an_emptied_list_sleeps_long_whatever_the_round_did() {
    let mut d = dcc();
    d.extend([(100, 32)]);
    let p = bg_policy(&d);
    let round = d.issue_round(&p, true);
    assert_eq!(round.issued(), 1);
    assert_eq!(d.next_wait(&p, &round), p.max_interval, "nothing is left to find");
}

#[test]
fn issued_runs_are_counted_for_the_report() {
    let mut d = dcc();
    d.extend([(100, 32), (200, 32)]);
    let p = d.init_policy(DiscardType::Force, 16, 0);
    d.issue_round(&p, true);
    assert_eq!(d.issued, 2);
}

/// A run leaves the parked lists and becomes IN FLIGHT, and the two counts are
/// disjoint: a build that reported the parked ones as queued would tell a tool
/// the device was working on requests it has already answered for.
#[test]
fn a_run_a_round_takes_is_in_flight_until_the_device_answers() {
    let mut d = dcc();
    d.extend([(100u32, 32u32), (200, 32)]);
    assert_eq!(d.cmd_count(), 2);
    assert_eq!(d.queued_count(), 0, "nothing has been handed over yet");
    let p = bg_policy(&d);
    let round = d.issue_round(&p, true);
    assert_eq!(round.runs.len(), 2);
    assert_eq!(d.cmd_count(), 0, "an issued run is no longer parked");
    assert_eq!(d.queued_count(), 2, "an issued run is in flight");
    d.completed(round.runs.len());
    assert_eq!(d.queued_count(), 0, "the device answered and nothing is outstanding");
    assert_eq!(d.issued, 2, "the report of work done only ever rises");
}
