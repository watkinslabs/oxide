//! Invalidating, splitting and merging — the part that decides whether a
//! cached answer is still the file's own block.

use super::*;
use crate::extent::limits::F2FS_MIN_EXTENT_LEN;

const MIN: u32 = F2FS_MIN_EXTENT_LEN;
const NO_CEILING: u32 = u32::MAX;
const INO: u32 = 1;

fn per(runs: &[Info]) -> Per {
    let mut p = Per::new();
    p.grab(INO);
    for &ei in runs { p.attach(INO, ei); p.note_largest(INO, &ei, Kind::Read); }
    p
}

fn read(p: &mut Per, ei: Info) -> Outcome {
    update_range(p, INO, ei, Kind::Read, false, NO_CEILING)
}

fn aged(p: &mut Per, ei: Info) -> Outcome {
    update_range(p, INO, ei, Kind::BlockAge, false, NO_CEILING)
}

/// Every run held, in file order.
fn runs(p: &Per) -> alloc::vec::Vec<Info> {
    p.trees[&INO].nodes.values().map(|n| n.ei).collect()
}

#[test]
fn a_change_to_an_empty_tree_is_recorded_as_it_stands() {
    let mut p = per(&[]);
    read(&mut p, Info::read(10, 4, 100));
    assert_eq!(runs(&p), alloc::vec![Info::read(10, 4, 100)]);
}

#[test]
fn a_zero_length_change_records_nothing() {
    let mut p = per(&[]);
    read(&mut p, Info::read(10, 0, 100));
    assert!(runs(&p).is_empty());
}

#[test]
fn a_change_with_no_blocks_behind_it_only_invalidates() {
    let mut p = per(&[Info::read(0, 4 * MIN, 1000)]);
    read(&mut p, Info::read(0, 4 * MIN, 0));
    assert!(runs(&p).is_empty(), "the old run is gone and nothing replaced it");
}

#[test]
fn a_change_inside_a_run_splits_it_into_the_two_parts_outside() {
    let mut p = per(&[Info::read(0, 200, 1000)]);
    read(&mut p, Info::read(70, 30, 5000));
    assert_eq!(runs(&p), alloc::vec![
        Info::read(0, 70, 1000),
        Info::read(70, 30, 5000),
        Info::read(100, 100, 1100),
    ]);
}

#[test]
fn the_tail_of_a_split_keeps_the_address_its_own_blocks_have() {
    let mut p = per(&[Info::read(0, 200, 1000)]);
    read(&mut p, Info::read(70, 30, 5000));
    let tail = runs(&p).into_iter().find(|e| e.fofs == 100).unwrap();
    assert_eq!(tail.blk, 1100, "file block 100 is volume block 1000 + 100");
}

#[test]
fn a_split_that_would_leave_a_short_tail_drops_it() {
    let mut p = per(&[Info::read(0, 200, 1000)]);
    read(&mut p, Info::read(70, 90, 5000));
    // Head of 70 is worth keeping; a tail of 40 is not.
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 70, 1000), Info::read(70, 90, 5000)]);
}

#[test]
fn a_split_that_would_leave_a_short_head_drops_it_and_re_bases_the_run() {
    let mut p = per(&[Info::read(0, 200, 1000)]);
    read(&mut p, Info::read(10, 90, 5000));
    assert_eq!(runs(&p), alloc::vec![Info::read(10, 90, 5000), Info::read(100, 100, 1100)]);
}

#[test]
fn a_split_leaving_nothing_worth_keeping_drops_the_whole_run() {
    let mut p = per(&[Info::read(0, 100, 1000)]);
    read(&mut p, Info::read(10, 40, 5000));
    assert_eq!(runs(&p), alloc::vec![Info::read(10, 40, 5000)]);
}

#[test]
fn the_age_cache_keeps_fragments_the_read_cache_would_refuse() {
    let mut p = Per::new();
    p.grab(INO);
    p.attach(INO, Info::aged(0, 100, 500_000, 900_000));
    // Far enough from its neighbours' age that it is a region of its own.
    aged(&mut p, Info::aged(10, 40, 7, 9_500));
    // No minimum length: an age is worth recording however short the run.
    assert_eq!(runs(&p).len(), 3);
    assert_eq!(runs(&p)[0], Info::aged(0, 10, 500_000, 900_000));
    assert_eq!(runs(&p)[1], Info::aged(10, 40, 7, 9_500));
    assert_eq!(runs(&p)[2].fofs, 50);
    assert_eq!(runs(&p)[2].len, 50);
}

#[test]
fn neighbouring_age_runs_from_the_same_region_are_not_kept_apart() {
    let mut p = Per::new();
    p.grab(INO);
    p.attach(INO, Info::aged(0, 100, 500, 9_000));
    // Ages within the region the format calls the same age: one run, not three.
    aged(&mut p, Info::aged(10, 40, 7, 9_500));
    assert_eq!(runs(&p), alloc::vec![Info::aged(0, 100, 500, 9_000)]);
}

#[test]
fn a_split_stops_when_the_inode_is_already_holding_all_the_runs_it_may() {
    let mut p = per(&[Info::read(0, 200, 1000)]);
    // One run held, and a ceiling of one: the tail has nowhere to go.
    update_range(&mut p, INO, Info::read(70, 30, 5000), Kind::Read, false, 1);
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 70, 1000), Info::read(70, 30, 5000)]);
}

#[test]
fn a_change_continuing_the_run_before_it_extends_that_run() {
    let mut p = per(&[Info::read(0, 100, 1000)]);
    read(&mut p, Info::read(100, 50, 1100));
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 150, 1000)]);
}

#[test]
fn a_change_the_run_after_it_continues_extends_that_run_backwards() {
    let mut p = per(&[Info::read(100, 50, 1100)]);
    read(&mut p, Info::read(50, 50, 1050));
    assert_eq!(runs(&p), alloc::vec![Info::read(50, 100, 1050)]);
}

#[test]
fn a_change_filling_the_gap_between_two_runs_makes_one_run_of_all_three() {
    let mut p = per(&[Info::read(0, 100, 1000), Info::read(150, 50, 1150)]);
    read(&mut p, Info::read(100, 50, 1100));
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 200, 1000)]);
    assert_eq!(p.node_count(), 1, "the run in front was released, not left behind");
}

#[test]
fn a_change_adjacent_in_the_file_but_not_on_the_volume_stays_its_own_run() {
    let mut p = per(&[Info::read(0, 100, 1000)]);
    read(&mut p, Info::read(100, 50, 9000));
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 100, 1000), Info::read(100, 50, 9000)]);
}

#[test]
fn the_longest_run_is_reported_as_changed_when_it_changes() {
    let mut p = Per::new();
    p.grab(INO);
    let out = read(&mut p, Info::read(0, 200, 1000));
    assert!(out.largest_updated);
    assert_eq!(p.largest(INO).len, 200);
}

#[test]
fn a_change_that_leaves_only_short_runs_gives_up_on_the_inode() {
    let mut p = per(&[Info::read(0, 10, 1000)]);
    assert_eq!(p.largest(INO).len, 10, "nothing long has ever been cached");
    let out = read(&mut p, Info::read(2, 5, 5000));
    assert!(out.gave_up);
}

#[test]
fn a_change_over_an_inode_with_a_long_run_does_not_give_up_on_it() {
    let mut p = per(&[Info::read(0, 200, 1000)]);
    let out = read(&mut p, Info::read(70, 30, 5000));
    assert!(!out.gave_up);
}

#[test]
fn a_change_mapping_nothing_that_existed_does_not_give_up_on_the_inode() {
    let mut p = per(&[]);
    let out = read(&mut p, Info::read(0, 5, 1000));
    assert!(!out.gave_up, "nothing was split, so nothing says the file is scattered");
}

#[test]
fn an_inode_already_given_up_on_takes_no_further_read_updates() {
    let mut p = per(&[]);
    update_range(&mut p, INO, Info::read(0, 4, 1000), Kind::Read, true, NO_CEILING);
    assert!(runs(&p).is_empty());
}

#[test]
fn an_age_update_carrying_no_age_invalidates_without_recording() {
    let mut p = Per::new();
    p.grab(INO);
    p.attach(INO, Info::aged(0, 100, 500, 9000));
    aged(&mut p, Info::invalidate(0, 100));
    assert!(runs(&p).is_empty());
}

#[test]
fn an_age_update_carrying_no_age_still_splits_what_it_overlaps() {
    let mut p = Per::new();
    p.grab(INO);
    p.attach(INO, Info::aged(0, 100, 500, 9000));
    aged(&mut p, Info::invalidate(40, 20));
    assert_eq!(runs(&p).len(), 2);
    assert_eq!((runs(&p)[0].fofs, runs(&p)[0].len), (0, 40));
    assert_eq!((runs(&p)[1].fofs, runs(&p)[1].len), (60, 40));
}

#[test]
fn neighbouring_age_runs_of_the_same_age_become_one() {
    let mut p = Per::new();
    p.grab(INO);
    p.attach(INO, Info::aged(0, 10, 500, 9000));
    aged(&mut p, Info::aged(10, 10, 500, 9000));
    assert_eq!(runs(&p), alloc::vec![Info::aged(0, 20, 500, 9000)]);
}

#[test]
fn a_change_spanning_several_runs_invalidates_every_one_of_them() {
    let mut p = per(&[
        Info::read(0, 100, 1000),
        Info::read(100, 100, 3000),
        Info::read(200, 100, 5000),
    ]);
    read(&mut p, Info::read(0, 300, 7000));
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 300, 7000)]);
}

#[test]
fn a_change_ending_inside_a_later_run_leaves_that_runs_tail() {
    let mut p = per(&[Info::read(0, 100, 1000), Info::read(100, 200, 3000)]);
    read(&mut p, Info::read(0, 150, 7000));
    assert_eq!(runs(&p), alloc::vec![Info::read(0, 150, 7000), Info::read(150, 150, 3050)]);
}

#[test]
fn no_run_ever_overlaps_another() {
    let mut p = per(&[Info::read(0, 400, 1000)]);
    for (fofs, len) in [(70u32, 80u32), (200, 70), (100, 65), (0, 64), (300, 90)] {
        read(&mut p, Info::read(fofs, len, 9000 + fofs));
        let rs = runs(&p);
        for w in rs.windows(2) { assert!(w[0].end() <= w[1].fofs, "{:?} overlaps {:?}", w[0], w[1]); }
    }
}
