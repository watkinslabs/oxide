//! What a candidate costs, and which candidate a bounded search settles on.
//!
//! The figures below are worked out by hand from the scale, the span and the
//! weight rather than read back from the code, because the arithmetic IS the
//! policy: a cost that is merely self-consistent would let the whole weight
//! split drift without a test noticing.

use super::*;
use alloc::vec::Vec;

/// Blocks a section holds when full, for the sections below.
const SEC_BLOCKS: u32 = 100;
/// The scale the two halves of a cost are computed on.
const SCALE: u64 = crate::atgc::DEFAULT_ACCURACY_CLASS;

/// A search over `entries`, given as `(segno, mtime, live)` in the order the
/// table walk reaches them. Every section is a candidate: the threshold is
/// zero, so what is being measured is the cost and not the filter.
fn search(weight: u32, entries: &[(u32, u64, u32)]) -> (Atgc, Vec<(u32, u32)>) {
    let mut a = Atgc::new();
    a.age_threshold = 0;
    a.age_weight = weight;
    a.begin();
    let mut table = Vec::new();
    for &(segno, mtime, live) in entries {
        a.add_candidate(segno, mtime, live, false);
        table.push((segno, live));
    }
    (a, table)
}

/// The live-block count the search costs through.
fn live(table: &[(u32, u32)]) -> impl Fn(u32) -> u32 + '_ {
    move |segno| table.iter().find(|(s, _)| *s == segno).map_or(0, |(_, l)| *l)
}

#[test]
fn a_search_with_no_candidate_answers_nothing() {
    let (a, t) = search(60, &[]);
    assert_eq!(a.lookup_victim(SEC_BLOCKS, &live(&t)), None);
}

#[test]
fn the_oldest_of_three_equally_full_sections_wins() {
    // Ages 0, 10 and 20 with the newest seen first, so the span is 0..=20.
    // Scale 10000 over a span of 21, weight 60, half of each section live:
    //   age(0)  = 10000 * 21/21 * 60 = 600000
    //   age(10) = 10000 * 11/21 * 60 = 314280
    //   age(20) = 10000 *  1/21 * 60 =  28560
    //   empty   = 10000 * 50/100 * 40 = 200000  for all three
    let (a, t) = search(60, &[(1, 20, 50), (2, 10, 50), (3, 0, 50)]);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.segno, 3);
    assert_eq!(p.age, 600_000);
    assert_eq!(p.cost, u32::MAX - 800_000);
}

#[test]
fn the_scale_and_span_are_the_ones_the_arithmetic_assumes() {
    // The hand-worked figures above rest on the scale being the class rather
    // than the span-derived cap, which holds for every span a volume has.
    assert_eq!(SCALE, 10_000);
    assert_eq!(Atgc::accuracy(21), SCALE);
    assert_eq!(Atgc::accuracy(1), SCALE);
    // Only an absurd span drops it below the class.
    assert!(Atgc::accuracy(u64::MAX / 1000) < SCALE);
}

#[test]
fn all_weight_on_emptiness_picks_the_emptiest_whatever_its_age() {
    //   empty(50) = 10000 * 50/100 * 100 = 500000
    //   empty(90) = 10000 * 10/100 * 100 = 100000
    //   empty(10) = 10000 * 90/100 * 100 = 900000
    let (a, t) = search(0, &[(1, 20, 10), (2, 10, 90), (3, 0, 50)]);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.segno, 1, "the newest section, and the emptiest");
    assert_eq!(p.age, 0, "no weight on age means no age term at all");
    assert_eq!(p.cost, u32::MAX - 900_000);
}

#[test]
fn all_weight_on_age_picks_the_oldest_whatever_its_occupancy() {
    //   age(0) = 10000 * 21/21 * 100 = 1000000
    let (a, t) = search(100, &[(1, 20, 10), (2, 10, 90), (3, 0, 99)]);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.segno, 3, "the oldest, though it is nearly full");
    assert_eq!(p.age, 1_000_000);
    assert_eq!(p.cost, u32::MAX - 1_000_000);
}

#[test]
fn a_newer_but_emptier_section_can_still_win() {
    // Weight 10 over a span of 0..=40:
    //   age(0)  = 10000 * 41/41 * 10 = 100000, empty(99) = 10000*1/100*90 =   9000
    //   age(40) = 10000 *  1/41 * 10 =   2430, empty(0)  = 10000*100/100*90 = 900000
    let (a, t) = search(10, &[(1, 40, 0), (2, 0, 99)]);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.segno, 1, "the emptiness half outweighs four decades of age");
    assert_eq!(p.cost, u32::MAX - 902_430);
}

#[test]
fn the_search_stops_after_the_bound_and_keeps_what_it_found() {
    let (mut a, t) = search(10, &[(1, 40, 0), (2, 0, 99)]);
    a.max_candidate_count = 1;
    a.candidate_ratio = 0;
    assert_eq!(a.dirty_threshold(), 1);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.segno, 2, "only the oldest candidate was costed");
    assert_eq!(p.cost, u32::MAX - 109_000);
    a.max_candidate_count = 2;
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.segno, 1, "one more candidate of budget reaches the better one");
}

#[test]
fn two_candidates_of_equal_cost_leave_the_older_in_place() {
    // A span of 0..=99 makes both halves of the cost multiples of 5000, so
    // two candidates whose age and occupancy sum alike cost alike:
    //   age(m) = 10000 * (100-m)/100 * 50 = 5000 * (100-m)
    //   empty(L) = 10000 * (100-L)/100 * 50 = 5000 * (100-L)
    // (0, live 60) and (40, live 20) both sum to 5000 * 140.
    let (a, t) = search(50, &[(9, 99, 99), (1, 0, 60), (2, 40, 20)]);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    assert_eq!(p.cost, u32::MAX - 700_000);
    assert_eq!(p.segno, 1, "the tie goes to the older");
    assert_eq!(p.age, 500_000);
}

#[test]
fn a_volume_whose_sections_all_carry_one_age_still_answers() {
    let (a, t) = search(60, &[(1, 77, 10), (2, 77, 90)]);
    let p = a.lookup_victim(SEC_BLOCKS, &live(&t)).unwrap();
    // Span of one: every candidate's age term is the whole of the scale, so
    // emptiness decides and nothing divides by an empty span.
    assert_eq!(p.segno, 1);
    assert_eq!(p.age, SCALE * 60);
}

#[test]
fn a_section_that_holds_nothing_back_costs_the_ceiling_and_is_not_chosen() {
    // Weight zero and a full section: no age term, no emptiness term, so the
    // cost equals the ceiling a search opens at and cannot beat it.
    let (a, t) = search(0, &[(1, 10, SEC_BLOCKS)]);
    assert_eq!(a.lookup_victim(SEC_BLOCKS, &live(&t)), None);
}

#[test]
fn a_section_size_of_zero_does_not_divide_by_it() {
    let (a, t) = search(60, &[(1, 20, 0), (2, 0, 0)]);
    let p = a.lookup_victim(0, &live(&t)).unwrap();
    assert_eq!(p.segno, 2, "with no occupancy to weigh, age decides");
}
