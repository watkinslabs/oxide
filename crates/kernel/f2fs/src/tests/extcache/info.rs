//! What one run answers for, and what makes two runs one.

use super::*;
use crate::extent::limits::SAME_AGE_REGION;

#[test]
fn a_run_answers_for_its_own_blocks_and_no_others() {
    let ei = Info::read(10, 4, 100);
    assert!(!ei.covers(9));
    assert!(ei.covers(10) && ei.covers(13));
    assert!(!ei.covers(14));
}

#[test]
fn a_block_address_is_the_runs_start_plus_the_offset_into_it() {
    let ei = Info::read(10, 4, 100);
    assert_eq!(ei.block(10), Some(100));
    assert_eq!(ei.block(13), Some(103));
    assert_eq!(ei.block(14), None);
}

#[test]
fn read_runs_are_one_run_only_when_both_file_and_volume_are_contiguous() {
    let back = Info::read(0, 4, 100);
    assert!(mergeable(&back, &Info::read(4, 2, 104), Kind::Read));
    // Contiguous in the file, scattered on the volume: two runs.
    assert!(!mergeable(&back, &Info::read(4, 2, 200), Kind::Read));
    // Contiguous on the volume, a gap in the file: two runs.
    assert!(!mergeable(&back, &Info::read(5, 2, 104), Kind::Read));
}

#[test]
fn merging_is_directional() {
    let a = Info::read(0, 4, 100);
    let b = Info::read(4, 2, 104);
    assert!(mergeable(&a, &b, Kind::Read));
    assert!(!mergeable(&b, &a, Kind::Read));
}

#[test]
fn age_runs_are_one_run_while_their_ages_stay_within_the_same_region() {
    let back = Info::aged(0, 4, 1000, 5000);
    let at = Info::aged(4, 2, 1000 + SAME_AGE_REGION, 5000 + SAME_AGE_REGION);
    let past = Info::aged(4, 2, 1000 + SAME_AGE_REGION + 1, 5000);
    assert!(mergeable(&back, &at, Kind::BlockAge));
    assert!(!mergeable(&back, &past, Kind::BlockAge));
}

#[test]
fn an_age_run_is_split_by_either_half_of_the_region_test() {
    let back = Info::aged(0, 4, 1000, 5000);
    // Ages close, allocation counts far apart.
    let far = Info::aged(4, 2, 1000, 5000 + SAME_AGE_REGION + 1);
    assert!(!mergeable(&back, &far, Kind::BlockAge));
}

#[test]
fn the_region_test_is_symmetric_in_magnitude() {
    let back = Info::aged(0, 4, 5000, 9000);
    let below = Info::aged(4, 2, 5000 - SAME_AGE_REGION, 9000 - SAME_AGE_REGION);
    assert!(mergeable(&back, &below, Kind::BlockAge));
    let further = Info::aged(4, 2, 5000 - SAME_AGE_REGION - 1, 9000);
    assert!(!mergeable(&back, &further, Kind::BlockAge));
}

#[test]
fn setting_a_run_for_one_cache_leaves_the_other_caches_fields_alone() {
    let mut ei = Info { fofs: 1, len: 1, blk: 7, age: 42, last_blocks: 99 };
    set_info(&mut ei, 5, 3, 70, 0, 0, Kind::Read);
    assert_eq!((ei.fofs, ei.len, ei.blk), (5, 3, 70));
    assert_eq!((ei.age, ei.last_blocks), (42, 99));

    let mut ei = Info { fofs: 1, len: 1, blk: 7, age: 42, last_blocks: 99 };
    set_info(&mut ei, 5, 3, 70, 11, 12, Kind::BlockAge);
    assert_eq!((ei.fofs, ei.len, ei.blk), (5, 3, 7));
    assert_eq!((ei.age, ei.last_blocks), (11, 12));
}

#[test]
fn a_lookup_that_found_no_tree_is_not_a_lookup_at_all() {
    assert!(!Lookup::NoTree.consulted());
    assert!(Lookup::Miss.consulted());
    assert!(Lookup::Found(Info::read(0, 1, 5), Hit::Tree).consulted());
}

#[test]
fn only_a_found_lookup_yields_a_block() {
    let l = Lookup::Found(Info::read(10, 4, 100), Hit::Largest);
    assert_eq!(l.block(12), Some((102, Hit::Largest)));
    assert_eq!(l.block(99), None);
    assert_eq!(Lookup::Miss.block(12), None);
}

#[test]
fn the_cache_indices_are_the_positions_the_mount_counts_in() {
    assert_eq!(Kind::Read.index(), 0);
    assert_eq!(Kind::BlockAge.index(), 1);
}
