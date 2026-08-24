//! Bounded, resuming victim search, in sections.
//!
//! Two properties that only show up together: a search that stops early must
//! still make progress round the volume, and a search in sections must cost
//! and clean the whole section rather than one segment of it.

use alloc::vec::Vec;

use crate::volume::gc::victim::{
    pick_unit, pick_unit_with_valid_thresh, section_mtime, unit_cost, unit_eligible,
    unit_mtime_span, units, Found, Policy,
    Search, SegInfo, Unit, DEF_MAX_VICTIM_SEARCH,
};

/// Blocks per segment on a fixture volume.
const PER: u16 = 512;

fn seg(segno: u32, live: u16, mtime: u64) -> SegInfo {
    SegInfo { segno, live, mtime, current: false }
}

fn open(segno: u32, live: u16, mtime: u64) -> SegInfo {
    SegInfo { segno, live, mtime, current: true }
}

/// A table of `n` segments, every one half live and equally old.
fn flat(n: u32) -> Vec<SegInfo> { (0..n).map(|s| seg(s, PER / 2, 0)).collect() }

#[test]
fn one_segment_to_the_section_is_the_segment_itself() {
    let t = [seg(0, 40, 3), seg(1, 7, 9)];
    let us = units(&t, PER, 1);
    assert_eq!(us.len(), 2);
    assert_eq!(us[0], Unit { first: 0, live: 40, mtime: 3, open: false, dirty: true });
    assert_eq!(us[1], Unit { first: 1, live: 7, mtime: 9, open: false, dirty: true });
}

#[test]
fn a_section_costs_what_all_its_segments_cost() {
    let t = [seg(0, 10, 0), seg(1, 20, 0), seg(2, 1, 0), seg(3, 1, 0)];
    let us = units(&t, PER, 2);
    assert_eq!(us.len(), 2);
    assert_eq!((us[0].first, us[0].live), (0, 30));
    assert_eq!((us[1].first, us[1].live), (2, 2));
    // Greedy costs the blocks the section would make it move, so the cheap
    // section wins even though segment 2 alone is no cheaper than segment 3.
    let found = pick_unit(&us, PER, 2, Search::foreground(Policy::Greedy), &[]).unwrap();
    assert_eq!(found.segno, 2);
}

#[test]
fn a_section_a_log_is_writing_anywhere_in_is_never_a_victim() {
    let t = [seg(0, 5, 0), open(1, 5, 0), seg(2, 400, 0), seg(3, 400, 0)];
    let us = units(&t, PER, 2);
    assert!(!unit_eligible(&us[0]), "a log inside the section rules it out");
    assert!(unit_eligible(&us[1]));
    let found = pick_unit(&us, PER, 2, Search::foreground(Policy::Greedy), &[]).unwrap();
    assert_eq!(found.segno, 2, "the expensive section is the only candidate");
}

#[test]
fn a_section_with_nothing_partly_used_is_no_candidate() {
    // Full segments have nothing to give and empty ones yield nothing, and a
    // section made only of those two is worth no work at all.
    let t = [seg(0, 0, 0), seg(1, PER, 0), seg(2, 3, 0), seg(3, 0, 0)];
    let us = units(&t, PER, 2);
    assert!(!unit_eligible(&us[0]));
    assert!(unit_eligible(&us[1]));
    assert_eq!(
        pick_unit(&us, PER, 2, Search::foreground(Policy::Greedy), &[]).map(|f| f.segno),
        Some(2)
    );
}

#[test]
fn a_sections_age_is_weighted_by_where_its_live_blocks_are() {
    // The nearly-dead old segment must not age the section on the strength of
    // blocks that are gone.
    let old_and_empty = [seg(0, 0, 1_000), seg(1, 100, 10)];
    assert_eq!(section_mtime(&old_and_empty), 10);
    let both = [seg(0, 100, 0), seg(1, 100, 200)];
    assert_eq!(section_mtime(&both), 100, "equal weight, mean age");
    let lopsided = [seg(0, 300, 0), seg(1, 100, 200)];
    assert_eq!(section_mtime(&lopsided), 50);
    assert_eq!(section_mtime(&[seg(0, 0, 5)]), 0, "nothing live, no age");
}

#[test]
fn cost_benefit_over_sections_prefers_the_older_of_two_alike() {
    let t = [seg(0, 100, 900), seg(1, 100, 900), seg(2, 100, 5), seg(3, 100, 5)];
    let us = units(&t, PER, 2);
    let (lo, hi) = unit_mtime_span(&us);
    assert_eq!((lo, hi), (5, 900));
    let young = unit_cost(Policy::CostBenefit, &us[0], PER, 2, lo, hi);
    let old = unit_cost(Policy::CostBenefit, &us[1], PER, 2, lo, hi);
    assert!(old < young, "an older section is cheaper to justify cleaning");
    let found = pick_unit(&us, PER, 2, Search::foreground(Policy::CostBenefit), &[]).unwrap();
    assert_eq!(found.segno, 2);
}

#[test]
fn one_time_gc_live_ratio_ceiling_prefers_a_less_live_section() {
    let t = [seg(0, 90, 1_000), seg(1, 50, 0)];
    let us = units(&t, 100, 1);
    let found = pick_unit_with_valid_thresh(
        &us, 100, 1, Search::foreground(Policy::Greedy), &[], 80).unwrap();
    assert_eq!(found.segno, 1, "a section at or above the Linux ratio is max-cost");
}

#[test]
fn a_bounded_search_stops_after_the_candidates_it_is_allowed() {
    // Ten equally-costed candidates, the best sitting past the bound. A
    // bounded search must NOT find it — that is what being bounded means —
    // and an unbounded one must.
    let mut t = flat(10);
    t[7] = seg(7, 1, 0);
    let us = units(&t, PER, 1);
    let bounded = Search { policy: Policy::Greedy, offset: 0, max_search: 3 };
    assert_eq!(pick_unit(&us, PER, 1, bounded, &[]).unwrap().segno, 0);
    let whole = Search::foreground(Policy::Greedy);
    assert_eq!(pick_unit(&us, PER, 1, whole, &[]).unwrap().segno, 7);
}

#[test]
fn the_next_search_resumes_where_the_last_one_stopped() {
    let t = flat(10);
    let us = units(&t, PER, 1);
    let mut offset = 0;
    let mut seen: Vec<u32> = Vec::new();
    for _ in 0..4 {
        let s = Search { policy: Policy::Greedy, offset, max_search: 2 };
        let Found { segno, cursor } = pick_unit(&us, PER, 1, s, &[]).unwrap();
        seen.push(segno);
        offset = cursor;
    }
    // Without the resume every one of these searches would answer 0 and the
    // rest of the volume would never be looked at.
    assert_eq!(seen, [0, 2, 4, 6]);
}

#[test]
fn the_cursor_wraps_and_covers_the_whole_volume() {
    let t = flat(4);
    let us = units(&t, PER, 1);
    let mut offset = 0;
    let mut seen: Vec<u32> = Vec::new();
    for _ in 0..6 {
        let s = Search { policy: Policy::Greedy, offset, max_search: 1 };
        let f = pick_unit(&us, PER, 1, s, &[]).unwrap();
        seen.push(f.segno);
        offset = f.cursor;
    }
    assert_eq!(seen, [0, 1, 2, 3, 0, 1], "the sweep comes round again");
}

#[test]
fn the_cursor_steps_a_whole_section_at_a_time() {
    let t = flat(8);
    let us = units(&t, PER, 2);
    let s = Search { policy: Policy::Greedy, offset: 0, max_search: 1 };
    let f = pick_unit(&us, PER, 2, s, &[]).unwrap();
    assert_eq!((f.segno, f.cursor), (0, 2), "a section is two segments wide here");
    let s = Search { policy: Policy::Greedy, offset: f.cursor, max_search: 1 };
    assert_eq!(pick_unit(&us, PER, 2, s, &[]).unwrap().segno, 2);
}

#[test]
fn a_resumed_search_still_reaches_a_better_victim_behind_it() {
    // Bounded means "few candidates", not "only ahead": a search starting past
    // the cheapest section wraps and finds it, as long as the bound allows.
    let mut t = flat(6);
    t[1] = seg(1, 1, 0);
    let us = units(&t, PER, 1);
    let s = Search { policy: Policy::Greedy, offset: 3, max_search: DEF_MAX_VICTIM_SEARCH };
    assert_eq!(pick_unit(&us, PER, 1, s, &[]).unwrap().segno, 1);
}

#[test]
fn a_skipped_section_is_not_costed_against_the_bound() {
    // A section already tried and refused must not consume the search's
    // allowance, or a handful of stubborn sections would starve the scan.
    let mut t = flat(6);
    t[5] = seg(5, 1, 0);
    let us = units(&t, PER, 1);
    // Two candidates' worth of allowance, spent from the start of the table,
    // never reaches the cheap section at the end.
    let s = Search { policy: Policy::Greedy, offset: 0, max_search: 2 };
    assert_eq!(pick_unit(&us, PER, 1, s, &[]).unwrap().segno, 0);
    // The same allowance, with the first four refused, reaches it — because a
    // refused section costs the search nothing.
    let s = Search { policy: Policy::Greedy, offset: 0, max_search: 2 };
    assert_eq!(pick_unit(&us, PER, 1, s, &[0, 1, 2, 3]).unwrap().segno, 5);
}

#[test]
fn an_offset_past_the_end_is_not_an_error() {
    let t = flat(3);
    let us = units(&t, PER, 1);
    let s = Search { policy: Policy::Greedy, offset: 900, max_search: 8 };
    assert!(pick_unit(&us, PER, 1, s, &[]).is_some());
    assert_eq!(pick_unit(&[], PER, 1, s, &[]), None, "an empty table has no victim");
}

#[test]
fn a_search_with_no_candidate_reports_none_and_does_not_move_the_cursor_on() {
    let t = [seg(0, 0, 0), open(1, 5, 0), seg(2, PER, 0)];
    let us = units(&t, PER, 1);
    let s = Search { policy: Policy::Greedy, offset: 0, max_search: 4 };
    assert_eq!(pick_unit(&us, PER, 1, s, &[]), None);
}
