//! Costing and choosing a victim, with no medium behind the table.

use crate::volume::gc::victim::{
    cb_cost, cost, eligible, greedy_cost, mtime_span, pick, Policy, SegInfo, COST_CEILING, PERCENT,
};

/// Blocks per segment every case here is costed against.
const PER: u16 = 512;

fn seg(segno: u32, live: u16, mtime: u64) -> SegInfo {
    SegInfo { segno, live, mtime, current: false }
}

fn open(segno: u32, live: u16, mtime: u64) -> SegInfo {
    SegInfo { segno, live, mtime, current: true }
}

#[test]
fn a_partly_used_segment_is_the_only_eligible_shape() {
    assert!(eligible(&seg(0, 1, 0), PER));
    assert!(eligible(&seg(0, PER - 1, 0), PER));
    assert!(!eligible(&seg(0, 0, 0), PER), "empty segment yields nothing");
    assert!(!eligible(&seg(0, PER, 0), PER), "full segment reclaims nothing");
    assert!(!eligible(&open(0, 1, 0), PER), "a log is appending to it");
}

#[test]
fn greedy_costs_a_segment_by_its_live_blocks() {
    assert_eq!(greedy_cost(0), 0);
    assert_eq!(greedy_cost(1), 1);
    assert_eq!(greedy_cost(PER), u64::from(PER));
    assert!(greedy_cost(3) < greedy_cost(4));
}

#[test]
fn greedy_picks_the_segment_with_the_fewest_live_blocks() {
    let t = [seg(0, 40, 0), seg(1, 7, 0), seg(2, 300, 0), seg(3, 8, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(1));
}

#[test]
fn greedy_breaks_a_tie_on_the_lower_segment_number() {
    let t = [seg(5, 9, 0), seg(2, 9, 0), seg(9, 9, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(2));
}

#[test]
fn a_current_segment_is_never_chosen_however_cheap_it_looks() {
    let t = [open(0, 1, 0), seg(1, 400, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(1));
    let only_open = [open(0, 1, 0), open(1, 2, 0)];
    assert_eq!(pick(&only_open, PER, Policy::Greedy, &[]), None);
}

#[test]
fn an_empty_segment_is_never_chosen() {
    let t = [seg(0, 0, 0), seg(1, 0, 0), seg(2, 5, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(2));
    let all_empty = [seg(0, 0, 0), seg(1, 0, 0)];
    assert_eq!(pick(&all_empty, PER, Policy::Greedy, &[]), None);
}

#[test]
fn a_full_segment_is_never_chosen() {
    let t = [seg(0, PER, 0), seg(1, PER - 1, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(1));
    let all_full = [seg(0, PER, 0), seg(1, PER, 0)];
    assert_eq!(pick(&all_full, PER, Policy::Greedy, &[]), None);
}

#[test]
fn an_empty_table_has_no_victim() {
    assert_eq!(pick(&[], PER, Policy::Greedy, &[]), None);
    assert_eq!(pick(&[], PER, Policy::CostBenefit, &[]), None);
}

#[test]
fn a_skipped_segment_is_passed_over() {
    let t = [seg(0, 3, 0), seg(1, 9, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(0));
    assert_eq!(pick(&t, PER, Policy::Greedy, &[0]), Some(1));
    assert_eq!(pick(&t, PER, Policy::Greedy, &[0, 1]), None);
}

#[test]
fn cost_benefit_prefers_the_older_of_two_equally_live_segments() {
    let t = [seg(0, 100, 900), seg(1, 100, 100), seg(2, 100, 500)];
    assert_eq!(pick(&t, PER, Policy::CostBenefit, &[]), Some(1));
    // Greedy cannot tell them apart at all, which is the difference the two
    // policies exist for.
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(0));
}

#[test]
fn cost_benefit_prefers_the_emptier_of_two_equally_old_segments() {
    let t = [seg(0, 400, 10), seg(1, 20, 10), seg(2, 400, 90)];
    assert_eq!(pick(&t, PER, Policy::CostBenefit, &[]), Some(1));
}

#[test]
fn cost_benefit_can_pass_over_the_emptiest_segment_for_a_much_older_one() {
    // Nearly-empty but written just now against half-live but ancient.
    let t = [seg(0, 4, 1_000), seg(1, 256, 0)];
    assert_eq!(pick(&t, PER, Policy::Greedy, &[]), Some(0));
    assert_eq!(pick(&t, PER, Policy::CostBenefit, &[]), Some(1));
}

#[test]
fn age_is_measured_only_over_segments_that_could_be_victims() {
    // The open log carries a timestamp far outside the candidates' range;
    // including it would change what "oldest" means for the rest.
    let with_log = [open(0, 5, 10_000), seg(1, 100, 10), seg(2, 100, 20)];
    assert_eq!(mtime_span(&with_log, PER), (10, 20));
    let without = [seg(1, 100, 10), seg(2, 100, 20)];
    assert_eq!(mtime_span(&without, PER), (10, 20));
    assert_eq!(
        pick(&with_log, PER, Policy::CostBenefit, &[]),
        pick(&without, PER, Policy::CostBenefit, &[])
    );
}

#[test]
fn a_table_with_no_candidates_has_no_span() {
    assert_eq!(mtime_span(&[], PER), (0, 0));
    assert_eq!(mtime_span(&[seg(0, 0, 77)], PER), (0, 0));
}

#[test]
fn one_timestamp_everywhere_leaves_the_age_term_out() {
    // Every candidate is exactly as old as every other, so no benefit can be
    // claimed and the cost is the ceiling for all of them.
    assert_eq!(cb_cost(10, 5, 5, 5, PER), COST_CEILING);
    assert_eq!(cb_cost(400, 5, 5, 5, PER), COST_CEILING);
    let t = [seg(3, 400, 5), seg(1, 10, 5)];
    assert_eq!(pick(&t, PER, Policy::CostBenefit, &[]), Some(1));
}

#[test]
fn the_oldest_segment_gets_the_whole_age_weight_and_the_newest_none() {
    let oldest = cb_cost(0, 0, 0, 100, PER);
    let newest = cb_cost(0, 100, 0, 100, PER);
    assert_eq!(newest, COST_CEILING, "no age, no benefit");
    assert_eq!(oldest, COST_CEILING - PERCENT * PERCENT);
    assert!(oldest < newest);
}

#[test]
fn cost_benefit_falls_as_liveness_falls_at_equal_age() {
    let mostly_live = cb_cost(500, 0, 0, 100, PER);
    let half_live = cb_cost(256, 0, 0, 100, PER);
    let nearly_empty = cb_cost(8, 0, 0, 100, PER);
    assert!(nearly_empty < half_live);
    assert!(half_live < mostly_live);
}

#[test]
fn cost_benefit_never_underflows_on_a_full_segment() {
    // A hundred-percent-live segment leaves a zero benefit rather than a
    // wrapped cost, which would make the worst candidate look like the best.
    assert_eq!(cb_cost(PER, 0, 0, 100, PER), COST_CEILING);
    assert!(cb_cost(PER, 0, 0, u64::MAX, PER) <= COST_CEILING);
}

#[test]
fn a_timestamp_below_the_recorded_floor_does_not_wrap() {
    // A table whose span was taken elsewhere can hand a lower mtime than the
    // floor; the answer must stay a cost, not a huge negative rolled over.
    assert!(cb_cost(10, 0, 50, 100, PER) <= COST_CEILING);
}

#[test]
fn the_two_policies_agree_on_the_dispatcher_they_are_costed_through() {
    let s = seg(0, 33, 40);
    assert_eq!(cost(Policy::Greedy, &s, PER, 0, 100), greedy_cost(33));
    assert_eq!(cost(Policy::CostBenefit, &s, PER, 0, 100), cb_cost(33, 40, 0, 100, PER));
}

#[test]
fn a_zero_width_segment_is_costed_without_dividing_by_zero() {
    assert!(cb_cost(0, 0, 0, 10, 0) <= COST_CEILING);
}
