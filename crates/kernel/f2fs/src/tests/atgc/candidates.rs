//! Which sections are offered to a search, and which the search keeps.
//!
//! The threshold is the whole policy: without it the age-weighted cost still
//! prefers an almost-empty young section, and the cleaner degenerates into
//! the greedy one it exists to differ from. Every case below is therefore
//! about a section being kept or refused, not about what it costs.

use super::*;

/// A day, which is the unit the ages below are written in.
const DAY: u64 = 60 * 60 * 24;

fn am() -> Atgc { let mut a = Atgc::new(); a.begin(); a }

#[test]
fn a_fresh_search_holds_no_candidate_and_no_span() {
    let a = am();
    assert_eq!(a.victim_count(), 0);
    let (lo, hi) = a.mtime_span();
    assert!(hi < lo, "an empty span answers nothing rather than everything");
}

#[test]
fn a_section_younger_than_the_threshold_is_refused() {
    let mut a = am();
    // The newest thing seen is at 30 days; a section at 29 is one day old.
    a.add_candidate(1, 30 * DAY, 100, false);
    a.add_candidate(2, 29 * DAY, 100, false);
    assert_eq!(a.victim_count(), 0, "neither has aged a week behind the newest");
    a.add_candidate(3, 20 * DAY, 100, false);
    assert_eq!(a.victim_count(), 1, "ten days behind the newest clears a week");
}

#[test]
fn a_section_exactly_at_the_threshold_is_kept() {
    let mut a = am();
    a.add_candidate(1, 30 * DAY, 100, false);
    a.add_candidate(2, 30 * DAY - a.age_threshold, 100, false);
    assert_eq!(a.victim_count(), 1, "the bound refuses what is under it, not what is at it");
    let mut b = am();
    b.add_candidate(1, 30 * DAY, 100, false);
    b.add_candidate(2, 30 * DAY - b.age_threshold + 1, 100, false);
    assert_eq!(b.victim_count(), 0, "one second under it is under it");
}

#[test]
fn the_newest_end_widens_as_candidates_arrive_and_never_rewinds() {
    let mut a = am();
    a.add_candidate(1, 10 * DAY, 100, false);
    assert_eq!(a.mtime_span().1, 10 * DAY);
    a.add_candidate(2, 40 * DAY, 100, false);
    assert_eq!(a.mtime_span().1, 40 * DAY, "the newest end follows the newest seen");
    a.add_candidate(3, 20 * DAY, 100, false);
    assert_eq!(a.mtime_span().1, 40 * DAY, "an older arrival does not pull it back");
    // The first section was not a candidate when it arrived — nothing older
    // than it had been seen — and the widening does not admit it after the
    // fact. That is the ordering the walk imposes, and it is why a search
    // over the same table can differ from one over its reverse.
    assert_eq!(a.victim_count(), 1);
}

#[test]
fn the_oldest_end_narrows_as_candidates_arrive() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, 20 * DAY, 100, false);
    a.add_candidate(3, 10 * DAY, 100, false);
    assert_eq!(a.mtime_span(), (10 * DAY, 40 * DAY));
}

#[test]
fn a_search_resets_the_oldest_end_but_leaves_the_newest_alone() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, 10 * DAY, 100, false);
    a.release();
    a.begin();
    assert_eq!(a.mtime_span().1, 40 * DAY, "the volume's newest survives the search");
    assert!(a.mtime_span().0 > a.mtime_span().1, "the oldest end starts over");
    // Because the newest survived, a section that would have been the first
    // arrival of a fresh search is judged against it and refused.
    a.add_candidate(3, 39 * DAY, 100, false);
    assert_eq!(a.victim_count(), 0);
}

#[test]
fn releasing_forgets_the_candidates() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, 10 * DAY, 100, false);
    assert_eq!(a.victim_count(), 1);
    a.release();
    assert_eq!(a.victim_count(), 0);
}

#[test]
fn starting_a_search_forgets_candidates_an_abandoned_one_left() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, 10 * DAY, 100, false);
    assert_eq!(a.victim_count(), 1);
    a.begin();
    assert_eq!(a.victim_count(), 0, "a search opens on its own candidates only");
}

#[test]
fn two_sections_of_the_same_age_are_both_kept() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, 10 * DAY, 100, false);
    a.add_candidate(3, 10 * DAY, 100, false);
    assert_eq!(a.victim_count(), 2, "the segment number keeps them apart");
}

#[test]
fn a_section_with_no_live_block_is_refused_when_nothing_can_retire_it() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, 10 * DAY, 0, true);
    assert_eq!(a.victim_count(), 0, "no checkpoint means its blocks cannot come back");
    let mut b = am();
    b.add_candidate(1, 40 * DAY, 100, false);
    b.add_candidate(2, 10 * DAY, 0, false);
    assert_eq!(b.victim_count(), 1, "with checkpointing the same section is a candidate");
}

#[test]
fn a_section_with_no_age_at_all_is_refused() {
    let mut a = am();
    a.add_candidate(1, 40 * DAY, 100, false);
    a.add_candidate(2, crate::atgc::INVALID_MTIME, 100, false);
    assert_eq!(a.victim_count(), 0);
    assert_eq!(a.mtime_span().1, 40 * DAY, "and it does not drag the span to the end of time");
}

#[test]
fn the_search_bound_is_the_larger_of_the_count_and_the_share() {
    let mut a = am();
    a.max_candidate_count = 10;
    a.candidate_ratio = 20;
    // Nothing collected: the fixed count is all there is.
    assert_eq!(a.dirty_threshold(), 10);
    // Twelve candidates: a fifth of them is two, so the count still holds.
    a.add_candidate(1, 400 * DAY, 100, false);
    for i in 0..12u32 { a.add_candidate(10 + i, u64::from(i) * DAY, 100, false); }
    assert_eq!(a.victim_count(), 12);
    assert_eq!(a.dirty_threshold(), 10, "a fifth of twelve is under the fixed count");
    a.candidate_ratio = 100;
    assert_eq!(a.dirty_threshold(), 12, "all of twelve is over it");
    a.candidate_ratio = 50;
    assert_eq!(a.dirty_threshold(), 10, "half of twelve is six, under the fixed count again");
    a.max_candidate_count = 1;
    assert_eq!(a.dirty_threshold(), 6, "with the count out of the way the share decides");
}

#[test]
fn the_defaults_are_the_ones_the_format_states() {
    let a = Atgc::new();
    assert!(!a.enabled);
    assert_eq!(a.candidate_ratio, 20);
    assert_eq!(a.max_candidate_count, 10);
    assert_eq!(a.age_weight, 60);
    assert_eq!(a.age_threshold, 7 * DAY);
}
