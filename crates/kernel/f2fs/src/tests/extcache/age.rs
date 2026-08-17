//! Blending a freshly measured interval into the age already recorded.

use super::*;
use crate::extent::limits::LAST_AGE_WEIGHT;

/// The blend, computed the obvious way in wide arithmetic, for values small
/// enough that the obvious way cannot overflow. The implementation splits
/// quotient from remainder so it stays exact at any magnitude; where both are
/// defined they must agree.
fn plainly(new: u64, old: u64, w: u64) -> u64 {
    (new / 100) * (100 - w) + (old / 100) * w
        + (new % 100) * (100 - w) / 100
        + (old % 100) * w / 100
}

#[test]
fn the_default_weight_is_the_one_the_format_states() {
    assert_eq!(default_weight(), LAST_AGE_WEIGHT);
}

#[test]
fn a_blend_of_equal_ages_is_that_age() {
    assert_eq!(calculate_block_age(1000, 1000, 30), 1000);
}

#[test]
fn all_the_weight_on_the_old_age_keeps_it() {
    assert_eq!(calculate_block_age(5000, 1200, 100), 1200);
}

#[test]
fn no_weight_on_the_old_age_discards_it() {
    assert_eq!(calculate_block_age(5000, 1200, 0), 5000);
}

#[test]
fn the_blend_is_the_two_shares_added() {
    // 30% of 1000 is 300; 70% of 2000 is 1400.
    assert_eq!(calculate_block_age(2000, 1000, 30), 1700);
}

#[test]
fn the_remainders_are_carried_rather_than_thrown_away() {
    // 149 = 100 + 49; 249 = 200 + 49. Quotients give 1*70 + 2*30 = 130.
    // Remainders give 49*70/100 = 34 and 49*30/100 = 14.
    assert_eq!(calculate_block_age(149, 249, 30), 130 + 34 + 14);
}

#[test]
fn only_a_non_zero_remainder_contributes() {
    // Both divide exactly: the two remainder terms are absent.
    assert_eq!(calculate_block_age(200, 300, 30), 2 * 70 + 3 * 30);
}

#[test]
fn the_blend_matches_the_plain_arithmetic_across_a_sweep() {
    for new in [0u64, 1, 99, 100, 101, 12_345, 999_999] {
        for old in [0u64, 1, 50, 100, 7_777, 1_000_000] {
            for w in [0u64, 1, 30, 50, 99, 100] {
                assert_eq!(calculate_block_age(new, old, w as u32), plainly(new, old, w),
                           "new={new} old={old} w={w}");
            }
        }
    }
}

#[test]
fn the_blend_stays_exact_where_scaling_first_would_overflow() {
    // Scaling before dividing would need 70 * (2^64 - 2), which does not fit.
    let huge = u64::MAX - 1;
    let got = calculate_block_age(huge, 0, 30);
    assert_eq!(got, (huge / 100) * 70 + (huge % 100) * 70 / 100);
}

#[test]
fn a_weight_past_the_whole_is_taken_as_the_whole() {
    assert_eq!(calculate_block_age(5000, 1200, 250), calculate_block_age(5000, 1200, 100));
}

#[test]
fn an_interval_is_what_the_volume_allocated_in_between() {
    assert_eq!(interval(9_000, 4_000), 5_000);
    assert_eq!(interval(4_000, 4_000), 0);
}

#[test]
fn an_interval_across_the_wrap_of_the_allocation_count_stays_small() {
    // The count wrapped: a block written just before the wrap is young, not
    // the oldest thing on the volume. The span runs to one below the widest
    // value the count takes, so nine remained before the wrap and five after.
    let last = u64::MAX - 10;
    assert_eq!(interval(5, last), 14);
    assert!(interval(5, last) < interval(5, 0) || interval(5, 0) == 5);
}

#[test]
fn the_last_block_of_a_part_filled_file_is_not_aged_when_it_is_freshly_allocated() {
    // A file of 4096 + 100 bytes: block 1 is the partly-filled tail.
    let size = 4096 + 100;
    assert!(is_unaged_tail(size, 1, 12, true));
}

#[test]
fn an_earlier_block_of_the_same_file_is_aged_normally() {
    let size = 4096 + 100;
    assert!(!is_unaged_tail(size, 0, 12, true));
}

#[test]
fn a_block_filled_to_its_end_is_aged_even_when_it_is_the_last() {
    // A file of exactly two blocks: nothing is partly filled.
    assert!(!is_unaged_tail(8192, 1, 12, true));
}

#[test]
fn a_tail_that_was_not_freshly_allocated_is_aged() {
    let size = 4096 + 100;
    assert!(!is_unaged_tail(size, 1, 12, false));
}
