//! Both caches through the surface a mount uses: the gates, the lookups, the
//! hand-back of an inode, and reclaim.

use super::*;
use crate::extent::limits::{DEF_MAX_READ_EXTENT_COUNT, F2FS_MIN_EXTENT_LEN};

const INO: u32 = 5;
const MIN: u32 = F2FS_MIN_EXTENT_LEN;

fn both() -> Caches { Caches::new(true, true) }

fn seeded(ei: Info) -> Caches {
    let mut c = both();
    c.init_trees(INO, Gate::regular(), Some(ei));
    c
}

#[test]
fn a_mount_that_asked_for_no_read_cache_gives_no_inode_one() {
    let c = Caches::new(false, true);
    assert!(!c.init_may_tree(Kind::Read, Gate::regular()));
    assert!(c.init_may_tree(Kind::BlockAge, Gate::regular()));
}

#[test]
fn a_mount_that_asked_for_no_age_cache_gives_no_inode_one() {
    let c = Caches::new(true, false);
    assert!(c.init_may_tree(Kind::Read, Gate::regular()));
    assert!(!c.init_may_tree(Kind::BlockAge, Gate::regular()));
}

#[test]
fn only_a_regular_file_is_read_cached() {
    let c = both();
    assert!(c.init_may_tree(Kind::Read, Gate::regular()));
    assert!(!c.init_may_tree(Kind::Read, Gate::directory()));
}

#[test]
fn a_directory_is_age_cached_because_its_blocks_are_placed_like_any_other() {
    let c = both();
    assert!(c.init_may_tree(Kind::BlockAge, Gate::directory()));
}

#[test]
fn a_compressed_file_has_no_offset_to_block_map_worth_caching() {
    let c = both();
    let g = Gate { compressed: true, ..Gate::regular() };
    assert!(!c.may_tree(Kind::Read, INO, g));
    assert!(!c.may_tree(Kind::BlockAge, INO, g));
}

#[test]
fn a_compressed_file_on_a_volume_nothing_can_write_is_read_cached() {
    let c = both();
    let g = Gate { compressed: true, readonly_volume: true, ..Gate::regular() };
    assert!(c.may_tree(Kind::Read, INO, g));
}

#[test]
fn a_file_marked_cold_has_an_age_that_says_nothing() {
    let c = both();
    let g = Gate { cold: true, ..Gate::regular() };
    assert!(!c.may_tree(Kind::BlockAge, INO, g));
    assert!(c.may_tree(Kind::Read, INO, g), "coldness says nothing about its blocks");
}

#[test]
fn an_inode_that_may_not_be_cached_must_not_carry_a_stored_run_either() {
    let mut c = both();
    let clear = c.init_read_tree(INO, Gate::directory(), Some(Info::read(0, 4, 100)));
    assert!(clear, "the caller is told to clear the run the inode stores");
    assert!(c.no_extent(INO));
}

#[test]
fn an_uncacheable_inode_with_no_stored_run_needs_nothing_cleared() {
    let mut c = both();
    assert!(!c.init_read_tree(INO, Gate::directory(), None));
}

#[test]
fn the_run_an_inode_stores_seeds_its_cache() {
    let mut c = seeded(Info::read(0, 8, 100));
    assert_eq!(c.lookup_block(INO, 3).block(3), Some((103, Hit::Largest)));
}

#[test]
fn a_stored_run_of_no_length_seeds_nothing() {
    let mut c = seeded(Info::read(0, 0, 100));
    assert_eq!(c.lookup(Kind::Read, INO, 0), Lookup::Miss);
    assert_eq!(c.node_count(Kind::Read), 0);
}

#[test]
fn an_inode_with_no_tree_is_not_a_cache_miss() {
    let mut c = both();
    assert_eq!(c.lookup(Kind::Read, 99, 0), Lookup::NoTree);
    assert!(!c.lookup(Kind::Read, 99, 0).consulted());
}

#[test]
fn an_inode_with_a_tree_and_no_run_for_the_offset_is_a_miss() {
    let mut c = seeded(Info::read(0, 8, 100));
    assert_eq!(c.lookup(Kind::Read, INO, 500), Lookup::Miss);
    assert!(c.lookup(Kind::Read, INO, 500).consulted());
}

#[test]
fn the_longest_run_answers_before_the_tree_is_consulted() {
    let mut c = seeded(Info::read(0, 8, 100));
    let (_, how) = c.lookup(Kind::Read, INO, 1).found().unwrap();
    assert_eq!(how, Hit::Largest);
}

#[test]
fn a_run_the_longest_does_not_cover_is_answered_by_the_tree() {
    let mut c = seeded(Info::read(0, 8, 100));
    c.update_range(Kind::Read, INO, Info::read(50, 4, 900));
    // A later change moves the front cache off the run being asked for.
    c.update_range(Kind::Read, INO, Info::read(80, 4, 700));
    let (ei, how) = c.lookup(Kind::Read, INO, 51).found().unwrap();
    assert_eq!(ei.blk, 900);
    assert_eq!(how, Hit::Tree);
}

#[test]
fn asking_twice_for_the_same_run_is_answered_by_the_front_cache_the_second_time() {
    let mut c = seeded(Info::read(0, 8, 100));
    c.update_range(Kind::Read, INO, Info::read(50, 4, 900));
    c.update_range(Kind::Read, INO, Info::read(80, 4, 700));
    assert_eq!(c.lookup(Kind::Read, INO, 51).found().unwrap().1, Hit::Tree);
    assert_eq!(c.lookup(Kind::Read, INO, 52).found().unwrap().1, Hit::Cached);
}

#[test]
fn a_run_just_recorded_is_the_one_the_next_lookup_tries_first() {
    let mut c = seeded(Info::read(0, 8, 100));
    c.update_range(Kind::Read, INO, Info::read(50, 4, 900));
    assert_eq!(c.lookup(Kind::Read, INO, 51).found().unwrap().1, Hit::Cached);
}

#[test]
fn the_age_cache_has_no_longest_run_shortcut() {
    let mut c = both();
    c.init_age_tree(INO, Gate::regular());
    c.update_range(Kind::BlockAge, INO, Info::aged(0, 100, 7, 9000));
    // Far enough away not to merge, and enough to move the front cache.
    c.update_range(Kind::BlockAge, INO, Info::aged(500, 4, 9_000_000, 9_000_000));
    let (_, how) = c.lookup(Kind::BlockAge, INO, 1).found().unwrap();
    assert_eq!(how, Hit::Tree, "the age cache answers only from its tree");
}

#[test]
fn giving_up_on_an_inode_throws_its_read_runs_away() {
    let mut c = seeded(Info::read(0, 10, 100));
    let out = c.update_range(Kind::Read, INO, Info::read(2, 5, 900));
    assert!(out.gave_up);
    assert!(c.no_extent(INO));
    assert_eq!(c.node_count(Kind::Read), 0);
    assert_eq!(c.lookup(Kind::Read, INO, 3), Lookup::Miss);
}

#[test]
fn an_inode_given_up_on_stops_taking_read_updates() {
    let mut c = seeded(Info::read(0, 10, 100));
    c.update_range(Kind::Read, INO, Info::read(2, 5, 900));
    c.update_range(Kind::Read, INO, Info::read(0, 4 * MIN, 7000));
    assert_eq!(c.node_count(Kind::Read), 0);
}

#[test]
fn dropping_an_inodes_caches_leaves_nothing_that_can_answer() {
    let mut c = seeded(Info::read(0, 4 * MIN, 100));
    c.init_age_tree(INO, Gate::regular());
    c.update_range(Kind::BlockAge, INO, Info::aged(0, 10, 7, 9000));
    c.drop_trees(INO);
    assert_eq!(c.lookup(Kind::Read, INO, 1), Lookup::Miss);
    assert_eq!(c.lookup(Kind::BlockAge, INO, 1), Lookup::Miss);
    assert_eq!(c.largest(INO), None);
}

#[test]
fn an_inode_that_still_has_a_name_keeps_its_runs_parked() {
    let mut c = seeded(Info::read(0, 4 * MIN, 100));
    c.destroy(INO, 1);
    assert_eq!(c.zombie_count(Kind::Read), 1);
    assert_eq!(c.node_count(Kind::Read), 1, "the runs are still there to be reused");
}

#[test]
fn opening_a_parked_inode_again_brings_its_runs_back() {
    let mut c = seeded(Info::read(0, 4 * MIN, 100));
    c.destroy(INO, 1);
    c.init_trees(INO, Gate::regular(), None);
    assert_eq!(c.zombie_count(Kind::Read), 0);
    assert_eq!(c.lookup_block(INO, 3).block(3), Some((103, Hit::Largest)));
}

#[test]
fn an_inode_whose_last_name_is_gone_is_freed_outright() {
    let mut c = seeded(Info::read(0, 4 * MIN, 100));
    c.destroy(INO, 0);
    assert_eq!(c.tree_count(Kind::Read), 0);
    assert_eq!(c.node_count(Kind::Read), 0);
    assert_eq!(c.zombie_count(Kind::Read), 0);
}

#[test]
fn a_tree_with_no_runs_is_freed_rather_than_parked() {
    let mut c = both();
    c.init_trees(INO, Gate::regular(), None);
    c.destroy(INO, 1);
    assert_eq!(c.tree_count(Kind::Read), 0);
}

#[test]
fn giving_up_on_an_inode_is_forgotten_when_the_inode_is() {
    let mut c = seeded(Info::read(0, 10, 100));
    c.update_range(Kind::Read, INO, Info::read(2, 5, 900));
    assert!(c.no_extent(INO));
    c.destroy(INO, 0);
    assert!(!c.no_extent(INO), "the number can be handed to another file");
}

#[test]
fn a_shrink_of_a_cache_the_mount_does_not_keep_frees_nothing() {
    let mut c = Caches::new(false, true);
    assert_eq!(c.shrink(Kind::Read, 8), 0);
}

#[test]
fn a_shrink_frees_what_it_is_asked_for_and_says_how_much() {
    let mut c = both();
    c.init_trees(INO, Gate::regular(), None);
    c.update_range(Kind::Read, INO, Info::read(0, MIN, 100));
    c.update_range(Kind::Read, INO, Info::read(10 * MIN, MIN, 900));
    assert_eq!(c.node_count(Kind::Read), 2);
    assert_eq!(c.shrink(Kind::Read, 1), 1);
    assert_eq!(c.node_count(Kind::Read), 1);
}

#[test]
fn the_memory_a_cache_holds_grows_with_what_it_holds() {
    let mut c = both();
    let empty = c.mem_bytes(Kind::Read);
    c.init_trees(INO, Gate::regular(), Some(Info::read(0, 4, 100)));
    assert!(c.mem_bytes(Kind::Read) > empty);
}

#[test]
fn the_entry_ceiling_starts_where_the_format_puts_it() {
    let mut c = both();
    assert_eq!(c.max_read_extent_count(), DEF_MAX_READ_EXTENT_COUNT);
    c.set_max_read_extent_count(7);
    assert_eq!(c.max_read_extent_count(), 7);
}

#[test]
fn a_lowered_entry_ceiling_stops_a_split_keeping_its_tail() {
    let mut c = both();
    c.init_trees(INO, Gate::regular(), Some(Info::read(0, 200, 1000)));
    c.set_max_read_extent_count(1);
    c.update_range(Kind::Read, INO, Info::read(70, 30, 5000));
    assert_eq!(c.node_count(Kind::Read), 2, "head and the change, but no tail");
}

#[test]
fn a_first_age_starts_the_count_from_now() {
    let mut c = both();
    c.init_age_tree(INO, Gate::regular());
    let (got, look) = c.new_block_age(INO, 0, true, 5_000, 0, 12);
    assert_eq!(got, Some((0, 5_000)));
    assert_eq!(look, Lookup::Miss, "a tree was consulted, so the mount counts it");
}

#[test]
fn a_second_age_is_the_interval_blended_with_the_first() {
    let mut c = both();
    c.init_age_tree(INO, Gate::regular());
    c.update_range(Kind::BlockAge, INO, Info::aged(0, 1, 1_000, 4_000));
    let (got, _) = c.new_block_age(INO, 0, false, 9_000, 0, 12);
    // Interval 5000 blended with a recorded age of 1000 at the default weight.
    let want = crate::extent::age::calculate_block_age(5_000, 1_000, c.last_age_weight());
    assert_eq!(got, Some((want, 9_000)));
}

#[test]
fn a_recorded_age_of_zero_is_replaced_rather_than_blended() {
    let mut c = both();
    c.init_age_tree(INO, Gate::regular());
    c.update_range(Kind::BlockAge, INO, Info::aged(0, 1, 0, 4_000));
    let (got, _) = c.new_block_age(INO, 0, false, 9_000, 0, 12);
    assert_eq!(got, Some((5_000, 9_000)));
}

#[test]
fn the_part_filled_last_block_of_a_growing_file_records_no_age() {
    let mut c = both();
    c.init_age_tree(INO, Gate::regular());
    let (got, look) = c.new_block_age(INO, 1, true, 5_000, 4096 + 100, 12);
    assert_eq!(got, None);
    assert!(!look.consulted(), "nothing was looked at, so nothing is counted");
}

#[test]
fn an_age_classifies_a_block_by_the_two_thresholds() {
    let mut c = both();
    c.set_hot_data_age_threshold(100);
    c.set_warm_data_age_threshold(1_000);
    assert_eq!(c.temperature(0), Temperature::Hot);
    assert_eq!(c.temperature(99), Temperature::Hot);
    assert_eq!(c.temperature(100), Temperature::Warm);
    assert_eq!(c.temperature(999), Temperature::Warm);
    assert_eq!(c.temperature(1_000), Temperature::Cold);
}

#[test]
fn every_run_held_is_in_the_reclaim_order_whatever_was_done_to_it() {
    let mut c = both();
    c.init_trees(INO, Gate::regular(), Some(Info::read(0, 400, 1000)));
    for (fofs, len) in [(70u32, 80u32), (200, 70), (100, 65), (0, 64), (300, 90)] {
        c.update_range(Kind::Read, INO, Info::read(fofs, len, 9000 + fofs));
        let per = c.per(Kind::Read);
        let held: usize = per.trees.values().map(|t| t.nodes.len()).sum();
        assert_eq!(held, per.lru.len(), "a run outside the order can never be reclaimed");
    }
}
