//! Age-threshold cleaning, driven against a real volume.
//!
//! Three things are wired and each has a way of being silently absent, which
//! is what these check:
//!
//! - the POLICY: a search that costs candidates by age rather than by how few
//!   blocks they hold. Absent, the cleaner still works and still reports
//!   progress, and nothing says the age half never ran.
//! - the LOG: what an ahead-of-demand pass moves goes to a log of its own, so
//!   old blocks land beside old blocks. Absent, the occupancy row the report
//!   publishes for it stays zero forever and reads exactly like an idle log.
//! - the ATTRIBUTION: every segment a pass empties is charged to the policy
//!   the pass ran under. Absent, six of the seven rows are permanently zero
//!   and the seventh is the whole total.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::stats::counters::{gc_mode, Counters};
use crate::stats::sample::General;
use crate::test_image::{self, MAIN_BLKADDR, ROOT_INO};
use crate::uapi::*;
use crate::volume::{map::Mapped, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);
const FILE_BLOCKS: usize = 4;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

fn seg_of(addr: u32) -> u32 { (addr - MAIN_BLKADDR) / BLKS_PER_SEG }

fn addr_of(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    let inode = v.read_inode(ino).unwrap();
    match v.map_block(&inode, ino, index).unwrap() {
        Mapped::At(a) => a,
        other => panic!("{other:?}"),
    }
}

fn payload(blocks: usize) -> Vec<u8> {
    (0..blocks * BLKSIZE).map(|i| ((i / BLKSIZE) * 71 + (i % 253)) as u8).collect()
}

/// A volume with one file whose data segment no log holds open, so it is a
/// candidate at all, and with two of its four blocks dead so cleaning it is
/// worth something.
fn victim_volume() -> (Volume<MemImage>, u32, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &payload(FILE_BLOCKS)).unwrap();
    let victim = seg_of(addr_of(&v, ino, 0));
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.write_file(ino, BLKSIZE as u64, b"BBBB").unwrap();
    (v, ino, victim)
}

/// Turn the policy on the way a volume that has aged into it does: the
/// threshold is what gates it, and a tool may lower the threshold.
fn enable_age_policy(v: &mut Volume<MemImage>) {
    let am = v.atgc_mut();
    am.age_threshold = 0;
    am.enabled = true;
}

#[test]
fn the_policy_is_off_on_a_volume_too_young_for_it() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    assert!(!v.atgc_enabled(), "a fresh volume has no ages worth comparing");
    assert_eq!(v.search_victim_by_age(&[]), None);
}

#[test]
fn the_age_policy_finds_the_section_the_ordinary_search_would_have_to_cost() {
    let (mut v, _, victim) = victim_volume();
    enable_age_policy(&mut v);
    let found = v.search_victim_by_age(&[]).expect("no candidate was collected");
    assert_eq!(found.segno, victim);
}

/// A section a log is still filling is never a candidate, whatever its age:
/// cleaning it would move blocks out from under the writer appending to it.
#[test]
fn a_section_a_log_holds_open_is_never_an_age_candidate() {
    let (mut v, _, victim) = victim_volume();
    enable_age_policy(&mut v);
    assert!(v.search_victim_by_age(&[]).is_some());
    // Point a log back at the victim and it stops being offered.
    v.curseg[CURSEG_COLD_DATA].segno = victim;
    assert_eq!(v.search_victim_by_age(&[]), None);
}

/// The whole point of the threshold: a section younger than it is refused
/// outright rather than merely costed badly.
#[test]
fn a_threshold_no_section_reaches_leaves_the_search_with_nothing() {
    let (mut v, _, _) = victim_volume();
    enable_age_policy(&mut v);
    assert!(v.search_victim_by_age(&[]).is_some());
    v.atgc_mut().age_threshold = u64::MAX;
    assert_eq!(v.search_victim_by_age(&[]), None);
}

/// Every emptied segment is charged to the policy the pass ran under, and to
/// no other. Six of the seven rows can only ever be non-zero through this.
#[test]
fn a_cleaned_segment_is_charged_to_the_policy_the_pass_ran_under() {
    for mode in [gc_mode::NORMAL, gc_mode::IDLE_CB, gc_mode::IDLE_AT,
                 gc_mode::URGENT_HIGH, gc_mode::URGENT_LOW, gc_mode::URGENT_MID] {
        let (mut v, _, victim) = victim_volume();
        let policy = crate::volume::gc::Policy::Greedy;
        v.gc_one_segment_as(policy, mode).unwrap();
        let c = v.counters();
        assert_eq!(c.gc_reclaimed_segs[mode], 1, "mode {mode} did not record its segment");
        let others: u32 = (0..gc_mode::MAX).filter(|&m| m != mode)
            .map(|m| c.gc_reclaimed_segs[m]).sum();
        assert_eq!(others, 0, "mode {mode} charged a segment to another row");
        let _ = victim;
    }
}

/// The figure the report publishes is the counter, so a pass moves the row a
/// reader is actually looking at.
#[test]
fn the_report_shows_the_segments_each_policy_emptied() {
    let (mut v, _, _) = victim_volume();
    v.gc_one_segment_as(crate::volume::gc::Policy::CostBenefit, gc_mode::IDLE_CB).unwrap();
    let c = v.counters();
    let g = General::sample(&mut v, &c).unwrap();
    assert_eq!(g.gc_reclaimed_segs[gc_mode::IDLE_CB], 1);
    let text = crate::stats::partition(&g, "vda", 0, 0);
    assert!(text.contains("Reclaimed segs"));
}

/// An ahead-of-demand pass on a mount that places by age writes what it moves
/// into the log of its own, and the report's row for that log then names a
/// real segment instead of nothing.
#[test]
fn the_age_pass_writes_through_its_own_log_and_the_report_shows_it() {
    let (mut v, _, _) = victim_volume();
    enable_age_policy(&mut v);
    let g = General::sample(&mut v, &Counters::new()).unwrap();
    assert_eq!(g.curseg[CURSEG_ALL_DATA_ATGC], NULL_SEGNO,
               "the log holds a segment before anything used it");
    v.gc_background_age(gc_mode::IDLE_AT).unwrap().expect("no victim was cleaned");
    let c = v.counters();
    assert_eq!(c.gc_reclaimed_segs[gc_mode::IDLE_AT], 1);
    let g = General::sample(&mut v, &c).unwrap();
    assert_ne!(g.curseg[CURSEG_ALL_DATA_ATGC], NULL_SEGNO,
               "the age log took nothing, so the report's row stays empty");
    let text = crate::stats::partition(&g, "vda", 0, 0);
    let row = text.lines().find(|l| l.contains("ATGC   data")).expect("no ATGC row");
    assert!(!row.contains("       0        0        0        0"),
            "the ATGC row is still all zeroes: {row}");
}

/// The blocks it moved are still the file's, byte for byte. A log that placed
/// them somewhere the owner does not point at is a cleaner that loses data.
#[test]
fn what_the_age_pass_moved_is_still_the_files_data() {
    let (mut v, ino, _) = victim_volume();
    enable_age_policy(&mut v);
    let before = { let i = v.read_inode(ino).unwrap(); v.read_whole(&i, ino).unwrap() };
    v.gc_background_age(gc_mode::IDLE_AT).unwrap().expect("no victim was cleaned");
    let after = { let i = v.read_inode(ino).unwrap(); v.read_whole(&i, ino).unwrap() };
    assert_eq!(before, after);
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                               crate::opts::Options::defaults(), true).unwrap();
    let i = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&i, ino).unwrap(), after);
}

/// With the policy off, the ahead-of-demand pass falls back rather than
/// declining: a volume whose sections are all young still needs cleaning.
#[test]
fn an_age_pass_on_a_mount_without_the_policy_still_cleans() {
    let (mut v, _, victim) = victim_volume();
    assert!(!v.atgc_enabled());
    let cleaned = v.gc_background_age(gc_mode::NORMAL).unwrap();
    assert_eq!(cleaned, Some(victim));
}

/// The log is not one of the six the checkpoint records, so nothing about it
/// reaches the medium — but it must be a real log while mounted.
#[test]
fn the_age_log_is_past_the_ones_the_checkpoint_records() {
    assert_eq!(CURSEG_ALL_DATA_ATGC, NR_CURSEG_TYPE - 1);
    assert!(CURSEG_ALL_DATA_ATGC >= NR_CURSEG_PERSIST_TYPE);
    assert_eq!(crate::volume::curseg::log_for(crate::volume::Kind::AtgcData, 6),
               CURSEG_ALL_DATA_ATGC);
    assert_eq!(crate::volume::curseg::log_for(crate::volume::Kind::AtgcData, 2),
               CURSEG_ALL_DATA_ATGC);
    let v = test_image::with_root().mount_rw().unwrap();
    assert_eq!(v.logs().len(), NR_CURSEG_TYPE);
    assert_eq!(v.logs()[CURSEG_ALL_DATA_ATGC].segno, NULL_SEGNO);
}

/// The free-id cache's two figures reach the report. Both read zero for the
/// life of a mount that never fills the cache, which is the state the report
/// was in before there was a cache at all.
#[test]
fn the_report_shows_what_the_free_id_cache_holds() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    for i in 0..4u32 {
        let name = [b'f', b'0' + i as u8];
        v.create(ROOT_INO, &name, &spec(), None).unwrap();
    }
    let (free, alloc, avail) = v.free_nid_counts();
    assert!(free > 0, "the cache holds no free id after four files were created");
    assert_eq!(alloc, 0, "an id was left recorded as handed out");
    assert!(avail > 0);
    let c = v.counters();
    let g = General::sample(&mut v, &c).unwrap();
    assert_eq!((g.free_nids, g.alloc_nids, g.avail_nids), (free, alloc, avail));
    let text = crate::stats::partition(&g, "vda", 0, 0);
    assert!(text.contains("free_nids"));
}

/// A file created and removed leaves the cache holding the id, not counting
/// it as still handed out — the state that would leak an id per file.
#[test]
fn an_id_is_never_left_recorded_as_handed_out() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    for i in 0..6u32 {
        let name = [b'f', b'0' + i as u8];
        let ino = v.create(ROOT_INO, &name, &spec(), None).unwrap();
        v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
        v.remove(ROOT_INO, &name, false, NOW).unwrap();
        assert_eq!(v.free_nid_counts().1, 0, "an id stayed handed out after round {i}");
    }
}
