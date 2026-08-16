//! Cleaning a real volume, proved by remounting it.
//!
//! Every fixture here builds the shape a cleaner is meant to find and cannot
//! be handed by the allocator alone: a segment with live blocks in it that no
//! log is appending to. The log is moved off it deliberately, which is also
//! what writes the segment's summary block — the only record of who owns each
//! block, and the record the cleaner cannot work without.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, MAIN_BLKADDR, ROOT_INO, SEG_MAIN};
use crate::uapi::*;
use crate::volume::gc::victim::Policy;
use crate::volume::{map::Mapped, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);
/// Blocks the fixture file is written with.
const FILE_BLOCKS: usize = 4;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// Which segment an address falls in. # C: O(1)
fn seg_of(addr: u32) -> u32 { (addr - MAIN_BLKADDR) / BLKS_PER_SEG }

/// The address of one of a file's blocks.
fn addr_of(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    let inode = v.read_inode(ino).unwrap();
    match v.map_block(&inode, ino, index).unwrap() {
        Mapped::At(a) => a,
        _ => panic!("the file's block is not a block"),
    }
}

fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

/// Commit and mount the same bytes again — the only proof a change reached
/// the medium.
fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// Bytes distinct in every block and at every offset, so a block copied to
/// the wrong place or read from the wrong place shows up.
fn payload(blocks: usize) -> Vec<u8> {
    (0..blocks * BLKSIZE).map(|i| ((i / BLKSIZE) * 71 + (i % 253)) as u8).collect()
}

/// A volume with one four-block file whose data segment no log holds open.
fn victim_volume() -> (Volume<MemImage>, u32, u32, Vec<u8>) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let data = payload(FILE_BLOCKS);
    v.write_file(ino, 0, &data).unwrap();
    let victim = seg_of(addr_of(&v, ino, 0));
    // Sealing the log's segment writes its summary block out and moves the
    // log elsewhere, which is what makes the segment a candidate at all.
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    (v, ino, victim, data)
}

/// Rewrite the head of block `index`, which kills the copy in the victim.
fn kill_block(v: &mut Volume<MemImage>, ino: u32, index: usize, mark: &[u8]) -> Vec<u8> {
    v.write_file(ino, (index * BLKSIZE) as u64, mark).unwrap();
    whole(v, ino)
}

#[test]
fn the_fixture_leaves_a_segment_no_log_is_writing_to() {
    let (v, ino, victim, _) = victim_volume();
    assert_eq!(v.seg_valid(victim), FILE_BLOCKS as u16);
    assert!(!v.is_current(victim), "a log must not still hold the victim");
    for i in 0..FILE_BLOCKS as u64 {
        assert_eq!(seg_of(addr_of(&v, ino, i)), victim);
    }
}

#[test]
fn cleaning_a_partly_dead_segment_empties_it() {
    let (mut v, ino, victim, _) = victim_volume();
    kill_block(&mut v, ino, 0, b"AAAA");
    kill_block(&mut v, ino, 1, b"BBBB");
    assert_eq!(v.seg_valid(victim), 2, "two of four copies are dead");
    let moved = v.gc_segment(victim).unwrap();
    assert_eq!(moved, 2, "only the survivors move");
    assert_eq!(v.seg_valid(victim), 0);
}

#[test]
fn cleaning_moves_the_survivors_out_of_the_victim() {
    let (mut v, ino, victim, _) = victim_volume();
    kill_block(&mut v, ino, 0, b"AAAA");
    let before: Vec<u32> = (1..FILE_BLOCKS as u64).map(|i| addr_of(&v, ino, i)).collect();
    for a in &before { assert_eq!(seg_of(*a), victim); }
    v.gc_segment(victim).unwrap();
    for (n, i) in (1..FILE_BLOCKS as u64).enumerate() {
        let now = addr_of(&v, ino, i);
        assert_ne!(now, before[n], "the owner still names the old address");
        assert_ne!(seg_of(now), victim, "the copy did not leave the victim");
    }
}

#[test]
fn the_file_reads_back_byte_identical_through_a_remount() {
    let (mut v, ino, victim, _) = victim_volume();
    let expect = kill_block(&mut v, ino, 0, b"AAAA");
    v.gc_segment(victim).unwrap();
    assert_eq!(whole(&v, ino), expect, "still right in this mount");
    let v = remount(v);
    assert_eq!(whole(&v, ino), expect, "still right off the medium");
    assert_eq!(v.read_inode(ino).unwrap().size, (FILE_BLOCKS * BLKSIZE) as u64);
}

#[test]
fn the_data_survives_the_cleaned_segment_being_written_over() {
    let (mut v, ino, victim, _) = victim_volume();
    let expect = kill_block(&mut v, ino, 0, b"AAAA");
    let olds: Vec<u32> = (1..FILE_BLOCKS as u64).map(|i| addr_of(&v, ino, i)).collect();
    v.gc_segment(victim).unwrap();
    assert_eq!(v.seg_valid(victim), 0);
    // What reclaiming a segment means: those blocks are the allocator's now
    // and get written over. A file still pointing into them loses its data,
    // which is why the owner update is part of the migration and not an
    // afterthought.
    let junk = vec![0x5Au8; BLKSIZE];
    for a in &olds { v.write_block(*a, &junk).unwrap(); }
    assert_eq!(whole(&v, ino), expect);
    let v = remount(v);
    assert_eq!(whole(&v, ino), expect);
}

#[test]
fn the_cleaned_segment_is_free_and_is_what_the_allocator_hands_out_next() {
    let (mut v, ino, victim, _) = victim_volume();
    kill_block(&mut v, ino, 0, b"AAAA");
    assert_ne!(v.find_free_seg(victim - 1), Some(victim), "not free while it holds data");
    v.gc_segment(victim).unwrap();
    assert_eq!(v.seg_valid(victim), 0);
    assert_eq!(v.find_free_seg(victim - 1), Some(victim));
}

#[test]
fn cleaning_leaves_the_live_block_count_where_it_found_it() {
    let (mut v, ino, victim, _) = victim_volume();
    kill_block(&mut v, ino, 0, b"AAAA");
    let before = v.valid_block_count;
    let moved = v.gc_segment(victim).unwrap();
    assert_eq!(moved, 3);
    // Every migration is one block gained and one released, and so is every
    // node rewrite that carries a new address, so the total does not move.
    assert_eq!(v.valid_block_count, before);
    let mut v = remount(v);
    v.load_segments().unwrap();
    let total: u64 = (0..SEG_MAIN).map(|s| u64::from(v.seg_valid(s))).sum();
    assert_eq!(total, v.valid_block_count, "the table and the count agree");
}

#[test]
fn free_segments_go_up_when_the_survivors_fit_in_an_open_log() {
    let (mut v, ino, victim, _) = victim_volume();
    kill_block(&mut v, ino, 0, b"AAAA");
    let before = v.free_segment_count();
    let freed = v.collect(before + 1).unwrap();
    assert_eq!(freed, 1);
    assert_eq!(v.seg_valid(victim), 0);
    assert!(v.free_segment_count() > before, "the cleaner gained a segment");
}

#[test]
fn a_block_the_owner_moved_away_from_is_not_migrated() {
    let (mut v, ino, victim, _) = victim_volume();
    let stale = addr_of(&v, ino, 1);
    let expect = kill_block(&mut v, ino, 1, b"BBBB");
    assert_ne!(addr_of(&v, ino, 1), stale, "the block moved out of the victim");
    assert_eq!(v.seg_valid(victim), 3);
    // The segment table, made to disagree with the owner the way a lost
    // release would leave it.
    v.update_seg(stale, true).unwrap();
    assert_eq!(v.seg_valid(victim), 4);
    let moved = v.gc_segment(victim).unwrap();
    assert_eq!(moved, 3, "the disowned copy must stay where it is");
    assert_eq!(v.seg_valid(victim), 1, "and its bit with it");
    assert_eq!(whole(&v, ino), expect);
    let v = remount(v);
    assert_eq!(whole(&v, ino), expect);
}

#[test]
fn a_block_the_summary_disowns_is_not_migrated() {
    let (mut v, ino, victim, _) = victim_volume();
    let orphan = addr_of(&v, ino, 2);
    let at = sum_block_addr(v.super_block().ssa_blkaddr, victim);
    let mut sum = v.read_block(at).unwrap();
    let off = summary_off((orphan - MAIN_BLKADDR - victim * BLKS_PER_SEG) as usize);
    sum[off..off + SUMMARY_SIZE].fill(0);
    v.write_block(at, &sum).unwrap();
    let expect = whole(&v, ino);
    let moved = v.gc_segment(victim).unwrap();
    assert_eq!(moved, (FILE_BLOCKS - 1) as u32, "a block with no owner is not moved");
    assert_eq!(v.seg_valid(victim), 1);
    assert_eq!(addr_of(&v, ino, 2), orphan, "and it is left exactly where it was");
    let v = remount(v);
    assert_eq!(whole(&v, ino), expect);
}

#[test]
fn a_node_segment_is_cleaned_through_the_node_table() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let data = payload(2);
    v.write_file(ino, 0, &data).unwrap();
    let nseg = seg_of(v.node_addr(ino).unwrap());
    // Each rewrite moves the inode block, leaving the previous copy dead.
    for i in 0..3u8 { v.write_file(ino, 0, &[i; 8]).unwrap(); }
    let expect = whole(&v, ino);
    v.open_segment(CURSEG_WARM_NODE).unwrap();
    assert!(!v.is_current(nseg));
    let live = v.seg_valid(nseg);
    assert!(live > 0 && u32::from(live) < BLKS_PER_SEG, "a partly-dead node segment");
    let moved = v.gc_segment(nseg).unwrap();
    assert_eq!(u32::from(live), moved, "every live node moves");
    assert_eq!(v.seg_valid(nseg), 0);
    assert_ne!(seg_of(v.node_addr(ino).unwrap()), nseg);
    let v = remount(v);
    assert_eq!(whole(&v, ino), expect);
    assert_eq!(v.read_inode(ino).unwrap().size, (2 * BLKSIZE) as u64);
}

#[test]
fn a_read_only_mount_refuses_to_clean() {
    let mut v = test_image::with_root().mount().unwrap();
    assert!(!v.writable());
    assert_eq!(v.gc_segment(1), Err(Errno::Erofs));
    assert_eq!(v.gc_one_segment(), Err(Errno::Erofs));
    assert_eq!(v.collect(1), Err(Errno::Erofs));
    assert_eq!(v.collect_with(Policy::CostBenefit, 1), Err(Errno::Erofs));
}

#[test]
fn a_segment_a_log_is_writing_to_is_refused() {
    let (mut v, _, _, _) = victim_volume();
    let open = v.logs()[CURSEG_WARM_DATA].segno;
    assert!(v.is_current(open));
    assert_eq!(v.gc_segment(open), Err(Errno::Ebusy));
}

#[test]
fn a_segment_outside_the_main_area_is_refused() {
    let (mut v, _, _, _) = victim_volume();
    assert_eq!(v.gc_segment(SEG_MAIN), Err(Errno::Einval));
    assert_eq!(v.gc_segment(u32::MAX), Err(Errno::Einval));
}

#[test]
fn a_volume_with_nothing_worth_cleaning_reports_so_and_stops() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    assert_eq!(v.gc_one_segment().unwrap(), None);
    assert_eq!(v.collect(u32::MAX).unwrap(), 0, "an impossible target still terminates");
}

#[test]
fn one_pass_cleans_the_best_victim_and_leaves_the_rest() {
    let (mut v, ino, victim, _) = victim_volume();
    kill_block(&mut v, ino, 0, b"AAAA");
    assert_eq!(v.pick_victim(Policy::Greedy, &[]), Some(victim));
    assert_eq!(v.gc_one_segment().unwrap(), Some(victim));
    assert_eq!(v.seg_valid(victim), 0);
    assert_eq!(v.gc_one_segment().unwrap(), None, "nothing left worth cleaning");
}

#[test]
fn a_victim_that_will_not_empty_is_not_chosen_twice() {
    let (mut v, ino, victim, _) = victim_volume();
    let stale = addr_of(&v, ino, 1);
    kill_block(&mut v, ino, 1, b"BBBB");
    v.update_seg(stale, true).unwrap();
    // The target can never be met: the disowned bit keeps the segment live.
    let freed = v.collect(v.free_segment_count() + 3).unwrap();
    assert_eq!(freed, 0);
    assert_eq!(v.seg_valid(victim), 1);
}
