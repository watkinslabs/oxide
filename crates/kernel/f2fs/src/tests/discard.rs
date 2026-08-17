//! Announcing freed space, and the two rules that make it safe.

use super::*;
use crate::mode::S_IFREG;
use crate::opts::{DiscardUnit, Options};
use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 0);
const MAIN: u32 = test_image::MAIN_BLKADDR;

fn opts_with(discard: bool, unit: DiscardUnit) -> Options {
    let mut o = Options::defaults();
    o.discard = discard;
    o.discard_unit = unit;
    o
}

fn vol(o: Options) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_opts(o).unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    (v, ino)
}

#[test]
fn neighbouring_blocks_coalesce_into_one_run() {
    assert_eq!(coalesce(vec![10, 11, 12]), vec![(10, 3)]);
}

#[test]
fn a_gap_breaks_a_run() {
    assert_eq!(coalesce(vec![10, 11, 13]), vec![(10, 2), (13, 1)]);
}

#[test]
fn blocks_recorded_out_of_order_still_coalesce() {
    assert_eq!(coalesce(vec![12, 10, 11]), vec![(10, 3)]);
}

#[test]
fn a_block_recorded_twice_is_announced_once() {
    assert_eq!(coalesce(vec![10, 10, 11]), vec![(10, 2)]);
}

#[test]
fn nothing_recorded_is_nothing_to_announce() {
    assert!(coalesce(Vec::new()).is_empty());
}

#[test]
fn block_granularity_keeps_every_run() {
    let runs = vec![(MAIN, 1), (MAIN + 7, 3)];
    assert_eq!(at_granularity(runs.clone(), DiscardUnit::Block, MAIN, 1), runs);
}

#[test]
fn segment_granularity_drops_a_run_shorter_than_a_segment() {
    // Announcing a partial erase unit is work the device cannot use.
    let runs = vec![(MAIN, BLKS_PER_SEG - 1)];
    assert!(at_granularity(runs, DiscardUnit::Segment, MAIN, 1).is_empty());
}

#[test]
fn segment_granularity_keeps_a_whole_aligned_segment() {
    let runs = vec![(MAIN, BLKS_PER_SEG)];
    assert_eq!(at_granularity(runs, DiscardUnit::Segment, MAIN, 1), vec![(MAIN, BLKS_PER_SEG)]);
}

#[test]
fn segment_granularity_trims_a_run_to_its_aligned_middle() {
    // Rounding OUTWARD would announce blocks still in use, so the unaligned
    // head and the short tail are dropped, never extended.
    let runs = vec![(MAIN + 4, BLKS_PER_SEG * 2)];
    let out = at_granularity(runs, DiscardUnit::Segment, MAIN, 1);
    assert_eq!(out, vec![(MAIN + BLKS_PER_SEG, BLKS_PER_SEG)]);
}

#[test]
fn segment_granularity_drops_a_run_that_spans_a_boundary_without_filling_one() {
    let runs = vec![(MAIN + BLKS_PER_SEG - 2, 4)];
    assert!(at_granularity(runs, DiscardUnit::Segment, MAIN, 1).is_empty());
}

#[test]
fn section_granularity_needs_a_whole_section() {
    let secsize = BLKS_PER_SEG * 2;
    let runs = vec![(MAIN, BLKS_PER_SEG)];
    assert!(at_granularity(runs.clone(), DiscardUnit::Section, MAIN, 2).is_empty());
    let runs = vec![(MAIN, secsize)];
    assert_eq!(at_granularity(runs, DiscardUnit::Section, MAIN, 2), vec![(MAIN, secsize)]);
}

#[test]
fn a_mount_that_did_not_ask_announces_nothing() {
    let (mut v, ino) = vol(opts_with(false, DiscardUnit::Block));
    assert!(!v.discards());
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    v.write_file(ino, 0, &vec![2u8; 2 * BLKSIZE]).unwrap();
    v.commit().unwrap();
    assert!(v.take_discards().is_empty());
}

#[test]
fn a_freed_block_is_announced_after_the_checkpoint() {
    let (mut v, ino) = vol(opts_with(true, DiscardUnit::Block));
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let _ = v.take_discards();
    let inode = v.read_inode(ino).unwrap();
    let crate::volume::map::Mapped::At(old) = v.map_block(&inode, ino, 0).unwrap()
        else { panic!("no block") };
    v.write_file(ino, 0, &vec![2u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let runs = v.take_discards();
    assert!(runs.iter().any(|&(s, l)| old >= s && old < s + l), "the freed block was not announced");
}

#[test]
fn nothing_is_announced_before_the_checkpoint_that_freed_it() {
    // The released block is still referenced by the checkpoint on the medium;
    // announcing it first destroys what a crash would recover to.
    let (mut v, ino) = vol(opts_with(true, DiscardUnit::Block));
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let _ = v.take_discards();
    v.write_file(ino, 0, &vec![2u8; BLKSIZE]).unwrap();
    // No commit yet.
    assert!(v.is_dirty());
    let runs = v.take_discards();
    let inode = v.read_inode(ino).unwrap();
    let crate::volume::map::Mapped::At(live) = v.map_block(&inode, ino, 0).unwrap()
        else { panic!("no block") };
    assert!(!runs.iter().any(|&(s, l)| live >= s && live < s + l),
            "announced a block the current checkpoint still points at");
}

#[test]
fn a_block_that_came_back_into_use_is_not_announced() {
    // Freed and reallocated before the checkpoint: announcing it would erase
    // live data.
    let (mut v, ino) = vol(opts_with(true, DiscardUnit::Block));
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let _ = v.take_discards();
    let inode = v.read_inode(ino).unwrap();
    let crate::volume::map::Mapped::At(first) = v.map_block(&inode, ino, 0).unwrap()
        else { panic!("no block") };
    v.release_block(first).unwrap();
    // Hand the very same block straight back out.
    v.update_seg(first, true).unwrap();
    v.commit().unwrap();
    let runs = v.take_discards();
    assert!(!runs.iter().any(|&(s, l)| first >= s && first < s + l),
            "announced a block that is live again");
}

#[test]
fn draining_twice_announces_nothing_the_second_time() {
    let (mut v, ino) = vol(opts_with(true, DiscardUnit::Block));
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.write_file(ino, 0, &vec![2u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let first = v.take_discards();
    assert!(!first.is_empty());
    assert!(v.take_discards().is_empty());
}

#[test]
fn every_announced_block_is_dead_at_the_moment_it_is_announced() {
    // The invariant, stated whole and checked over a real workload.
    let (mut v, ino) = vol(opts_with(true, DiscardUnit::Block));
    for round in 0..6u8 {
        v.write_file(ino, 0, &vec![round; 3 * BLKSIZE]).unwrap();
        v.commit().unwrap();
        for (start, len) in v.take_discards() {
            for a in start..start + len {
                assert!(!v.block_is_live(a).unwrap(), "announced live block {a}");
            }
        }
    }
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), vec![5u8; 3 * BLKSIZE]);
}

#[test]
fn the_option_round_trips_through_its_own_rendering() {
    for unit in [DiscardUnit::Block, DiscardUnit::Segment, DiscardUnit::Section] {
        let mut o = Options::defaults();
        o.discard_unit = unit;
        let shown = crate::opts::show(&o, 0);
        assert_eq!(crate::opts::parse(Options::defaults(), &shown).unwrap().discard_unit, unit);
    }
}

#[test]
fn an_unknown_granularity_is_refused() {
    assert!(crate::opts::parse(Options::defaults(), "discard_unit=page").is_err());
}
