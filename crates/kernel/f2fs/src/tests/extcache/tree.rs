//! One inode's runs, and the mount-wide order that decides what is dropped.

use super::*;
use crate::extent::info::Info;

fn per_with(ino: u32, runs: &[(u32, u32, u32)]) -> Per {
    let mut p = Per::new();
    p.grab(ino);
    for &(fofs, len, blk) in runs { p.attach(ino, Info::read(fofs, len, blk)); }
    p
}

#[test]
fn a_lookup_finds_the_run_starting_at_or_before_the_offset() {
    let p = per_with(1, &[(0, 4, 100), (10, 4, 200)]);
    let t = &p.trees[&1];
    assert_eq!(t.lookup(2).map(|(k, _)| k), Some(0));
    assert_eq!(t.lookup(12).map(|(k, _)| k), Some(10));
}

#[test]
fn an_offset_in_a_gap_is_not_covered_by_the_run_before_it() {
    let p = per_with(1, &[(0, 4, 100), (10, 4, 200)]);
    assert!(p.trees[&1].lookup(6).is_none());
}

#[test]
fn the_front_cache_answers_before_the_map_is_walked() {
    let mut p = per_with(1, &[(0, 4, 100), (10, 4, 200)]);
    p.touch(1, 10);
    assert_eq!(p.trees[&1].lookup(11), Some((10, Hit::Cached)));
    // An offset the cached run does not cover falls through to the map.
    assert_eq!(p.trees[&1].lookup(1), Some((0, Hit::Tree)));
}

#[test]
fn the_run_a_lookup_answered_from_is_the_one_the_next_lookup_tries_first() {
    let mut p = per_with(1, &[(0, 4, 100), (10, 4, 200)]);
    assert_eq!(p.trees[&1].lookup(1), Some((0, Hit::Tree)));
    p.touch(1, 0);
    assert_eq!(p.trees[&1].lookup(1), Some((0, Hit::Cached)));
}

#[test]
fn every_run_held_is_in_the_order_of_last_use() {
    let mut p = per_with(1, &[(0, 4, 100), (10, 4, 200)]);
    p.grab(2);
    p.attach(2, Info::read(0, 1, 900));
    assert_eq!(p.node_count(), 3);
    assert_eq!(p.lru.len(), 3);
    p.detach(1, 0);
    assert_eq!(p.node_count(), 2);
    assert_eq!(p.lru.len(), 2);
}

#[test]
fn dropping_the_run_the_front_cache_names_clears_it() {
    let mut p = per_with(1, &[(0, 4, 100)]);
    p.touch(1, 0);
    assert_eq!(p.trees[&1].cached, Some(0));
    p.detach(1, 0);
    assert_eq!(p.trees[&1].cached, None);
}

#[test]
fn re_basing_a_run_moves_it_in_both_structures() {
    let mut p = per_with(1, &[(0, 4, 100)]);
    p.touch(1, 0);
    p.rekey(1, 0, 2);
    assert!(p.trees[&1].nodes.contains_key(&2));
    assert!(!p.trees[&1].nodes.contains_key(&0));
    assert_eq!(p.trees[&1].cached, Some(2));
    assert_eq!(p.lru.values().copied().collect::<alloc::vec::Vec<_>>(), alloc::vec![(1, 2)]);
}

#[test]
fn the_longest_run_is_remembered_only_for_the_read_cache() {
    let mut p = per_with(1, &[]);
    p.note_largest(1, &Info::read(0, 8, 100), Kind::Read);
    assert_eq!(p.largest(1).len, 8);
    let mut q = Per::new();
    q.grab(1);
    q.note_largest(1, &Info::aged(0, 8, 1, 1), Kind::BlockAge);
    assert_eq!(q.largest(1).len, 0);
}

#[test]
fn a_shorter_run_does_not_displace_the_longest() {
    let mut p = per_with(1, &[]);
    p.note_largest(1, &Info::read(0, 8, 100), Kind::Read);
    p.note_largest(1, &Info::read(20, 8, 300), Kind::Read);
    assert_eq!(p.largest(1).fofs, 0);
    p.note_largest(1, &Info::read(20, 9, 300), Kind::Read);
    assert_eq!(p.largest(1).fofs, 20);
}

#[test]
fn a_change_overlapping_the_longest_run_forgets_it() {
    let mut p = per_with(1, &[]);
    p.note_largest(1, &Info::read(10, 8, 100), Kind::Read);
    p.trees.get_mut(&1).unwrap().drop_largest(0, 4);
    assert_eq!(p.largest(1).len, 8, "a change before the run leaves it alone");
    p.trees.get_mut(&1).unwrap().drop_largest(12, 1);
    assert_eq!(p.largest(1).len, 0);
}

#[test]
fn the_longest_run_reports_its_change_once() {
    let mut p = per_with(1, &[]);
    p.note_largest(1, &Info::read(0, 8, 100), Kind::Read);
    assert!(p.take_largest_updated(1));
    assert!(!p.take_largest_updated(1));
}

#[test]
fn a_parked_tree_comes_back_to_life_when_the_inode_does() {
    let mut p = per_with(1, &[(0, 4, 100)]);
    p.make_zombie(1);
    assert_eq!(p.zombie_count(), 1);
    p.grab(1);
    assert_eq!(p.zombie_count(), 0);
    assert!(!p.trees[&1].zombie);
}

#[test]
fn a_shrink_frees_parked_trees_before_it_touches_a_live_run() {
    let mut p = Per::new();
    p.grab(1);
    p.attach(1, Info::read(0, 1, 100));
    p.grab(2);
    p.attach(2, Info::read(0, 1, 200));
    p.make_zombie(1);
    // Two units of work: the parked tree's one run, then the tree itself.
    assert_eq!(p.shrink(2), 2);
    assert!(!p.trees.contains_key(&1));
    assert_eq!(p.count(2), 1, "the live inode's run survived");
}

#[test]
fn a_shrink_past_the_parked_trees_takes_the_least_recently_used_run() {
    let mut p = per_with(1, &[(0, 1, 100), (10, 1, 200), (20, 1, 300)]);
    p.touch(1, 0);
    // Order of last use is now 10, 20, 0.
    assert_eq!(p.shrink(1), 1);
    assert!(!p.trees[&1].nodes.contains_key(&10));
    assert!(p.trees[&1].nodes.contains_key(&0));
}

#[test]
fn a_shrink_frees_no_more_than_it_was_asked_for() {
    let mut p = per_with(1, &[(0, 1, 100), (10, 1, 200), (20, 1, 300)]);
    assert_eq!(p.shrink(2), 2);
    assert_eq!(p.node_count(), 1);
}

#[test]
fn a_shrink_of_an_empty_cache_frees_nothing() {
    let mut p = Per::new();
    assert_eq!(p.shrink(8), 0);
}

#[test]
fn giving_up_a_tree_takes_its_runs_out_of_the_order_too() {
    let mut p = per_with(1, &[(0, 1, 100), (10, 1, 200)]);
    p.remove_tree(1);
    assert_eq!(p.node_count(), 0);
    assert_eq!(p.lru.len(), 0);
    assert_eq!(p.tree_count(), 0);
}
