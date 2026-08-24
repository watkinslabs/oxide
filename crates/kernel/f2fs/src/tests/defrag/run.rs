//! Defragmenting a real file on a real image, proved by remounting its bytes.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
const BLK: u64 = BLKSIZE as u64;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// A block whose every byte names it, so a block that moved to the wrong
/// place is a block whose contents say where it came from.
fn page(tag: u8) -> Vec<u8> { vec![tag; BLKSIZE] }

/// Three blocks written OUT OF ORDER, which is what scatters them: each write
/// takes the next address in the log, so the file's logical order and its
/// physical order end up unrelated.
fn scattered() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for index in [2u64, 0, 1] {
        v.write_file(ino, index * BLK, &page(index as u8 + 1)).unwrap();
        v.sync_data().unwrap();
    }
    // A checkpoint, so the sections the next one will need are not counted
    // against the rewrite: the gate asks whether there is room for BOTH.
    v.commit().unwrap();
    (v, ino)
}

fn addrs(v: &Volume<MemImage>, ino: u32, n: u64) -> Vec<u32> {
    (0..n).map(|i| v.mapped_addr(ino, i).unwrap().unwrap()).collect()
}

fn contents(v: &Volume<MemImage>, ino: u32, n: u64) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    let mut out = vec![0u8; (n * BLK) as usize];
    v.read_file(&inode, ino, 0, &mut out).unwrap();
    // One byte per block is enough: every byte of a block is the same tag.
    (0..n).map(|i| out[(i * BLK) as usize]).collect()
}

// ------------------------------------------------------------------- the move

#[test]
fn a_scattered_file_is_reported_scattered_and_a_written_one_is_not() {
    let (v, ino) = scattered();
    let a = addrs(&v, ino, 3);
    assert!(a[1] + 1 != a[2], "the fixture did not scatter the file: {a:?}");
}

#[test]
fn defragmenting_lays_the_blocks_out_in_file_order() {
    let (mut v, ino) = scattered();
    let moved = v.defragment_range(ino, 0, 3 * BLK).unwrap();
    assert_eq!(moved, 3 * BLK);
    assert_eq!(v.counters().defrag_blks, 3);
    let a = addrs(&v, ino, 3);
    assert_eq!(a[1], a[0] + 1);
    assert_eq!(a[2], a[1] + 1);
}

#[test]
fn the_bytes_survive_the_move_and_a_remount() {
    let (mut v, ino) = scattered();
    v.defragment_range(ino, 0, 3 * BLK).unwrap();
    let v = remount(v);
    assert_eq!(contents(&v, ino, 3), vec![1, 2, 3]);
}

#[test]
fn the_length_and_the_block_count_do_not_change() {
    let (mut v, ino) = scattered();
    let before = v.read_inode(ino).unwrap();
    v.defragment_range(ino, 0, 3 * BLK).unwrap();
    let after = v.read_inode(ino).unwrap();
    assert_eq!(after.size, before.size);
    assert_eq!(after.blocks, before.blocks);
}

#[test]
fn a_second_pass_finds_nothing_left_to_do() {
    let (mut v, ino) = scattered();
    assert_eq!(v.defragment_range(ino, 0, 3 * BLK).unwrap(), 3 * BLK);
    assert_eq!(v.defragment_range(ino, 0, 3 * BLK).unwrap(), 0);
}

#[test]
fn a_file_written_in_order_is_left_alone() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    for index in 0..3u64 { v.write_file(ino, index * BLK, &page(index as u8 + 1)).unwrap(); }
    v.commit().unwrap();
    let before = addrs(&v, ino, 3);
    assert_eq!(v.defragment_range(ino, 0, 3 * BLK).unwrap(), 0);
    assert_eq!(addrs(&v, ino, 3), before);
}

#[test]
fn holes_between_adjacent_blocks_are_not_fragmentation() {
    // Blocks 0 and 2 exist and are adjacent on the medium; block 1 is a hole.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"h", &spec(), None).unwrap();
    v.write_file(ino, 0, &page(1)).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, 2 * BLK, &page(3)).unwrap();
    v.sync_data().unwrap();
    assert_eq!(v.mapped_addr(ino, 1).unwrap(), None);
    let before = (v.mapped_addr(ino, 0).unwrap(), v.mapped_addr(ino, 2).unwrap());
    assert_eq!(v.defragment_range(ino, 0, 3 * BLK).unwrap(), 0);
    assert_eq!((v.mapped_addr(ino, 0).unwrap(), v.mapped_addr(ino, 2).unwrap()), before);
}

#[test]
fn a_hole_inside_a_scattered_range_is_left_a_hole() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"i", &spec(), None).unwrap();
    // Placed as each is written, which is what scatters them: a pair left
    // pending is placed together, in file order, and is not fragmented at all.
    for index in [3u64, 0] {
        v.write_file(ino, index * BLK, &page(index as u8 + 1)).unwrap();
        v.sync_data().unwrap();
    }
    v.commit().unwrap();
    assert_eq!(v.defragment_range(ino, 0, 4 * BLK).unwrap(), 2 * BLK);
    assert_eq!(v.mapped_addr(ino, 1).unwrap(), None);
    assert_eq!(v.mapped_addr(ino, 2).unwrap(), None);
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    let mut out = vec![0u8; 4 * BLKSIZE];
    v.read_file(&inode, ino, 0, &mut out).unwrap();
    assert_eq!(out[0], 1);
    assert_eq!(out[BLKSIZE], 0);
    assert_eq!(out[3 * BLKSIZE], 4);
}

// ------------------------------------------------------------------- the range

#[test]
fn the_range_stops_at_the_end_of_the_file() {
    let (mut v, ino) = scattered();
    // Asked for a hundred blocks; only the three that exist are moved.
    assert_eq!(v.defragment_range(ino, 0, 100 * BLK).unwrap(), 3 * BLK);
}

#[test]
fn a_range_past_the_end_of_the_file_moves_nothing() {
    let (mut v, ino) = scattered();
    assert_eq!(v.defragment_range(ino, 8 * BLK, 4 * BLK).unwrap(), 0);
}

#[test]
fn a_range_covering_one_block_is_never_fragmented() {
    let (mut v, ino) = scattered();
    let before = addrs(&v, ino, 3);
    assert_eq!(v.defragment_range(ino, BLK, BLK).unwrap(), 0);
    assert_eq!(addrs(&v, ino, 3), before);
}

// ---------------------------------------------------------------- the refusals

#[test]
fn a_read_only_mount_refuses() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.defragment_range(ROOT_INO, 0, BLK), Err(Errno::Erofs));
}

#[test]
fn a_pinned_file_is_refused_because_its_blocks_may_not_move() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"p", &spec(), None).unwrap();
    v.write_file(ino, 0, &page(1)).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    // Pinned after the fact: what matters here is the refusal, not the path
    // that set the promise.
    v.stamp_inode(ino, |b| b[crate::uapi::I_INLINE] |= crate::flags::PIN_FILE).unwrap();
    assert_eq!(v.defragment_range(ino, 0, BLK), Err(Errno::Einval));
}

#[test]
fn a_file_in_an_atomic_span_is_refused() {
    let (mut v, ino) = scattered();
    v.start_atomic_write(ino, false).unwrap();
    assert_eq!(v.defragment_range(ino, 0, 3 * BLK), Err(Errno::Einval));
}

#[test]
fn a_volume_with_no_free_section_left_says_try_again() {
    // Nowhere to put the copy, so the rewrite is refused BEFORE it starts:
    // a pass that stopped half way would leave the range in two places.
    let (mut v, ino) = scattered();
    let before = addrs(&v, ino, 3);
    v.load_segments().unwrap();
    let per = v.super_block().blks_per_seg() as u16;
    for e in v.sit.as_mut().unwrap().iter_mut() { e.vblocks = per; }
    assert_eq!(v.defragment_range(ino, 0, 3 * BLK), Err(Errno::Eagain));
    assert_eq!(addrs(&v, ino, 3), before);
}

#[test]
fn the_state_refusals_come_before_the_range_is_looked_at() {
    // An empty range on a file that could never be rewritten is told which
    // of the two stopped it: a caller told "nothing moved" would try again
    // with a bigger range and be told the same thing.
    let (mut v, ino) = scattered();
    v.start_atomic_write(ino, false).unwrap();
    assert_eq!(v.defragment_range(ino, 8 * BLK, 4 * BLK), Err(Errno::Einval));
}
