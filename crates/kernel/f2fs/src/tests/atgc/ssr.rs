//! Choosing a segment to REUSE, by nearness of age rather than by age alone.
//!
//! Reuse is the opposite question from cleaning: the caller has a write of a
//! known age and wants to put it beside data of the same age, so that the
//! segment they share falls due together instead of leaving one survivor to
//! be copied out later. So the walk goes OUTWARDS in both directions from the
//! wanted age, and the cost prefers the fullest segment that still has room —
//! a nearly-empty one would waste the slots it does have.

use super::*;
use alloc::vec::Vec;

/// Blocks a segment holds when full.
const PER_SEG: u32 = 100;
/// The age the caller is placing, which the walk starts from.
const TARGET: u64 = 21;

/// A search over `(segno, mtime, live)`, newest offered first so the span is
/// settled before the older candidates arrive.
fn search(entries: &[(u32, u64, u32)]) -> (Atgc, Vec<(u32, u32)>) {
    let mut a = Atgc::new();
    a.age_threshold = 0;
    a.begin();
    let mut table = Vec::new();
    for &(segno, mtime, live) in entries {
        a.add_candidate(segno, mtime, live, false);
        table.push((segno, live));
    }
    (a, table)
}

fn live(table: &[(u32, u32)]) -> impl Fn(u32) -> u32 + '_ {
    move |segno| table.iter().find(|(s, _)| *s == segno).map_or(0, |(_, l)| *l)
}

#[test]
fn a_search_with_no_candidate_answers_nothing() {
    let (a, t) = search(&[]);
    assert_eq!(a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)), None);
}

#[test]
fn the_walk_reaches_candidates_older_than_where_it_started() {
    // Ages 10, 20, 30; the wanted age lands the start on 20, so 10 is only
    // reachable by walking back from it.
    let (a, t) = search(&[(3, 30, 10), (2, 20, 10), (1, 10, 90)]);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 1);
    assert_eq!(p.cost, u32::MAX - 90);
}

#[test]
fn the_walk_reaches_candidates_newer_than_where_it_started() {
    let (a, t) = search(&[(3, 30, 90), (2, 20, 10), (1, 10, 10)]);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 3);
    assert_eq!(p.cost, u32::MAX - 90);
}

#[test]
fn the_fullest_segment_with_room_is_preferred() {
    let (a, t) = search(&[(3, 30, 20), (2, 20, 60), (1, 10, 40)]);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 2, "reuse wants the slots it does not waste");
    assert_eq!(p.cost, u32::MAX - 60);
}

#[test]
fn a_segment_with_no_room_at_all_is_passed_over() {
    let (a, t) = search(&[(3, 30, 20), (2, 20, PER_SEG), (1, 10, 40)]);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 1, "the fullest has no free slot, so the next fullest wins");
    assert_eq!(p.cost, u32::MAX - 40);
}

#[test]
fn equal_cost_goes_to_the_candidate_nearest_the_wanted_age() {
    // All three equally full, so only nearness separates them. Ages measured
    // from one past the newest: 21, 11 and 1 for the three candidates, and
    // the wanted age is 21 — which the oldest matches exactly.
    //
    // The start is the middle candidate, so the nearest one is reached
    // SECOND: a comparison that kept whatever it saw first would answer 2.
    let (a, t) = search(&[(3, 30, 50), (2, 20, 50), (1, 10, 50)]);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 1);
    assert_eq!(p.age, 31, "an exact match scores the whole span");
}

#[test]
fn the_walk_stops_at_the_bound_in_each_direction() {
    let (mut a, t) = search(&[(3, 30, 10), (2, 20, 10), (1, 10, 90)]);
    a.max_candidate_count = 1;
    a.candidate_ratio = 0;
    assert_eq!(a.dirty_threshold(), 1);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 2, "one candidate of budget reaches only where it started");
    a.max_candidate_count = 2;
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 1, "one more step back reaches the better one");
}

#[test]
fn a_wanted_age_below_every_candidate_starts_at_the_oldest() {
    let (a, t) = search(&[(3, 30, 10), (2, 20, 10), (1, 10, 90)]);
    let p = a.lookup_ssr_victim(0, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 1, "there is nothing older to walk back to");
}

#[test]
fn a_wanted_age_above_every_candidate_starts_at_the_newest() {
    let (mut a, t) = search(&[(3, 30, 90), (2, 20, 10), (1, 10, 10)]);
    a.max_candidate_count = 1;
    a.candidate_ratio = 0;
    let p = a.lookup_ssr_victim(u64::MAX, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 3, "the newest candidate is where a walk from beyond starts");
}

#[test]
fn a_volume_whose_candidates_all_carry_one_age_still_answers() {
    let (a, t) = search(&[(1, 77, 10), (2, 77, 90)]);
    let p = a.lookup_ssr_victim(TARGET, PER_SEG, &live(&t)).unwrap();
    assert_eq!(p.segno, 2);
}
