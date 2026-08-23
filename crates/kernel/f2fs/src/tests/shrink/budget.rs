//! How a reclaim budget is divided, and what a mount reports as reclaimable.

use super::*;
use crate::freenid::limits::MAX_FREE_NIDS;

#[test]
fn each_extent_cache_is_capped_at_a_quarter_of_the_budget() {
    let b = split(100);
    assert_eq!(b.age, 25);
    assert_eq!(b.read, 25);
    assert_eq!(b.nat, 25);
}

/// The half of the split that matters: a burst of pressure must not be able to
/// empty either extent cache, because every entry freed there is a block lookup
/// the next read pays for by walking the node tree.
#[test]
fn a_budget_larger_than_both_caches_still_only_takes_a_quarter_each() {
    let b = split(1_000_000);
    assert_eq!(b.age + b.read + b.nat, 750_000, "quarter of the budget stayed with the id cache");
}

#[test]
fn a_budget_too_small_to_divide_takes_nothing_from_the_extent_caches() {
    // Below four there is no quarter, and asking for zero is what leaves the
    // whole of a tiny budget to the cache that is cheap to refill.
    for nr in 0..4 {
        assert_eq!(split(nr), Budget { age: 0, read: 0, nat: 0 }, "nr = {nr}");
    }
    assert_eq!(split(4), Budget { age: 1, read: 1, nat: 1 });
}

#[test]
fn the_id_cache_is_asked_for_whatever_the_extent_caches_left() {
    assert_eq!(remaining(100, 0), 100);
    assert_eq!(remaining(100, 40), 60);
}

/// A pass that already met its target stops rather than going on to empty a
/// cache the machine was not asking it to touch.
#[test]
fn a_met_budget_asks_the_id_cache_for_nothing() {
    assert_eq!(remaining(100, 100), 0);
    assert_eq!(remaining(100, 250), 0, "an overshoot does not wrap into a huge budget");
}

#[test]
fn both_extent_caches_count_toward_what_could_be_freed() {
    assert_eq!(reclaimable(7, 11, 13, 0), 31);
}

/// Free ids are reclaimable only ABOVE the working set the cache keeps so that
/// creating a file does not have to scan the node table. Counting them all
/// would report memory that cannot be given back without buying a table scan.
#[test]
fn free_node_ids_count_only_above_the_working_set() {
    assert_eq!(reclaimable(0, 0, 0, MAX_FREE_NIDS), 0);
    assert_eq!(reclaimable(0, 0, 0, MAX_FREE_NIDS - 1), 0);
    assert_eq!(reclaimable(0, 0, 0, MAX_FREE_NIDS + 9), 9);
}

#[test]
fn a_mount_holding_nothing_offers_nothing() {
    assert_eq!(reclaimable(0, 0, 0, 0), 0);
}
