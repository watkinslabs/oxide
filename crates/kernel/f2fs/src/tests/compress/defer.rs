//! A compressed file on the DEFERRED path: what a write takes, what it leaves,
//! and what the placement decides.
//!
//! The property under test is that a compressed file no longer writes through.
//! A write takes the room and the owner's quota for the slots it will need,
//! writes a reservation into each of them and leaves the file's plain bytes in
//! the mapping; the codec, the choice between an image and plain blocks, and
//! every address are decided later, once, for the whole cluster.
//!
//! Every case here goes in through `write_file`, which is what a caller
//! actually reaches, so the routing into the compressed path is part of what is
//! being asserted rather than assumed. Each case names, in its own comment, the
//! line that turns it red.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::compress::plan;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, COMPRESS_ADDR, I_COMPRESS_ALGORITHM, I_FLAGS,
                  I_LOG_CLUSTER_SIZE, NEW_ADDR, NULL_ADDR};
use crate::volume::dnode::put32;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
/// Four blocks to a cluster, the narrowest width the format admits.
const LOG: u8 = 2;
const CS: usize = 1 << LOG;

/// A writable volume holding one compressed file, and that file's number.
/// # C: O(1 image)
fn with_compressed() -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"c", &spec, None).unwrap();
    v.stamp_inode(ino, |blk| {
        let f = le32(blk, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(blk, I_FLAGS, f);
        blk[I_COMPRESS_ALGORITHM] = crate::compress::algo::COMPRESS_LZ4;
        blk[I_LOG_CLUSTER_SIZE] = LOG;
    })
    .unwrap();
    (v, ino)
}

/// Bytes that compress into a single block. # C: O(n)
fn patterned(n: usize) -> Vec<u8> { (0..n).map(|i| ((i / 64) % 11) as u8).collect() }

/// One cluster's stored addresses. # C: O(cluster blocks)
fn addrs(v: &Volume<MemImage>, ino: u32, first: u64) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    let g = v.geometry(&inode).unwrap();
    v.cluster_addrs(&inode, ino, &g, first).unwrap()
}

/// # C: O(file bytes)
fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

/// The volume as a crash would leave it: the bytes that are ON THE MEDIUM,
/// mounted again. Nothing in memory survives, which is the point.
/// # C: O(image)
fn as_after_a_crash(v: &Volume<MemImage>) -> Volume<MemImage> {
    let bytes = v.source_ref().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// Leave `keep` blocks of the volume available to an ordinary allocation and
/// nothing more.
///
/// Through the root reserve, which is space an ordinary allocation may not
/// have, so the volume's own counts stay untouched and only what a write is
/// allowed to take changes.
/// # C: O(1)
fn leave_room_for(v: &mut Volume<MemImage>, keep: u64) {
    let left = v.checkpoint().user_block_count - v.valid_block_count;
    v.opts.reserve_root = (left - keep) as u32;
}

/// Reserve MORE than the volume has left, so any request for room is refused.
///
/// One block short of nothing rather than exactly nothing, because a slot whose
/// reservation is given back a moment before the request frees exactly the block
/// the request would take — so a volume with nothing spare still admits it, and
/// a case built on that measures nothing.
/// # C: O(1)
fn leave_no_room(v: &mut Volume<MemImage>) {
    let left = v.checkpoint().user_block_count - v.valid_block_count;
    v.opts.reserve_root = (left + 1) as u32;
}

// ------------------------------------------------------- the deferred window

#[test]
fn a_write_reserves_every_slot_it_needs_and_allocates_none() {
    // Allocation moved. Put it back at the write — have the compressed path
    // store the cluster as it goes — and these slots name blocks here.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    let a = addrs(&v, ino, 0);
    assert!(a.iter().all(|&x| x == NEW_ADDR), "the write chose blocks: {a:?}");
    assert_eq!(v.dirty_data_pages(ino), CS, "the bytes are not in the mapping");
    assert_eq!(plan::compressed_extent(&a), None, "the write already made an image");
}

#[test]
fn a_pending_compressed_write_is_readable() {
    // The read consults the mapping before the node tree. Remove that peek in
    // `read_file_inner` and a reserved cluster reads as zeroes.
    let (mut v, ino) = with_compressed();
    let data = patterned(CS * BLKSIZE);
    v.write_file(ino, 0, &data).unwrap();
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn nothing_of_a_pending_compressed_write_is_on_the_medium() {
    // The other half of the same fact, asserted where memory cannot help: the
    // image, the sentinel and the saving are all decided at the placement, so
    // a crash before it leaves a file that was never written.
    let (mut v, ino) = with_compressed();
    v.commit().unwrap();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    let after = as_after_a_crash(&v);
    assert_eq!(after.read_inode(ino).unwrap().size, 0, "an unplaced write reached the medium");
    let a = addrs(&after, ino, 0);
    assert!(a.iter().all(|&x| x == NULL_ADDR), "{a:?}");
}

#[test]
fn the_placement_chooses_the_shape_and_the_addresses() {
    // The one place either is decided. Leave the codec at the write and the
    // sentinel is already there before this flush.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    assert_ne!(addrs(&v, ino, 0)[0], COMPRESS_ADDR, "the write already chose the shape");
    v.sync_data().unwrap();
    let a = addrs(&v, ino, 0);
    let extent = plan::compressed_extent(&a).expect("the placement made no image");
    assert!(extent >= 2 && extent < CS, "image extent {extent} in {a:?}");
    assert!(a[extent..].iter().all(|&x| x == NEW_ADDR), "the tail was cleared: {a:?}");
    for &x in &a[1..extent] { assert!(v.sb_main_contains(x), "{a:?}"); }
    assert_eq!(v.dirty_data_pages(ino), 0, "pages stayed dirty after the placement");
}

#[test]
fn placing_a_cluster_does_not_forget_its_pages() {
    // The placement is putting the pages it holds at the addresses it chose,
    // so it is the one address change that must keep them. Give it the
    // page-dropping `set_holder_addr` and this read goes to the medium and
    // decompresses the image again.
    let (mut v, ino) = with_compressed();
    let data = patterned(CS * BLKSIZE);
    v.write_file(ino, 0, &data).unwrap();
    v.sync_data().unwrap();
    let before = v.data_cache_hits();
    assert_eq!(whole(&v, ino), data);
    assert!(v.data_cache_hits() > before, "the placed pages were dropped from the mapping");
}

#[test]
fn a_second_placement_moves_nothing() {
    // Placed exactly once. A flush that re-wrote a clean cluster would move
    // every block of it each time anything called one.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    v.sync_data().unwrap();
    let a = addrs(&v, ino, 0);
    v.sync_data().unwrap();
    v.sync_data().unwrap();
    assert_eq!(addrs(&v, ino, 0), a, "an idle flush rewrote the cluster");
}

#[test]
fn a_cluster_is_placed_once_however_many_of_its_pages_ask() {
    // Four dirty pages, one cluster, one image. A placement that ran per page
    // would compress the same bytes four times and leave three of the runs
    // stranded — visible here as a volume that has spent more blocks than the
    // image occupies.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    assert_eq!(v.dirty_data_pages(ino), CS, "the fixture depends on every page being dirty");
    let before = v.valid_block_count;
    v.sync_data().unwrap();
    assert_eq!(v.valid_block_count, before, "the placement spent room it did not hold");
    v.load_segments().unwrap();
    let live: u64 = (0..v.sb.segment_count_main).map(|s| u64::from(v.seg_valid(s))).sum();
    let a = addrs(&v, ino, 0);
    let image = plan::compressed_extent(&a).unwrap() - 1;
    // The file's own blocks, the inode's block, and nothing else: a cluster
    // placed more than once leaves the extra runs live in the segment table.
    assert!(live <= image as u64 + 2, "the segment table holds {live} blocks for {a:?}");
}

// -------------------------------------------------------- room and the owner

#[test]
fn placing_reserved_slots_needs_no_further_room() {
    // THE invariant the whole arrangement buys. The reservations already hold
    // the room, so the placement may spend it and must not ask for it again.
    // Hand the allocator `NULL_ADDR` instead of the reservation in `lay_out`'s
    // data arm and this volume — which has nothing left to give — cannot place
    // the write it has already accepted.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    leave_no_room(&mut v);
    assert_eq!(v.sync_data(), Ok(()), "the placement asked for room it already held");
    let a = addrs(&v, ino, 0);
    assert!(plan::compressed_extent(&a).is_some(), "{a:?}");
    assert_eq!(whole(&v, ino), patterned(CS * BLKSIZE));
}

#[test]
fn making_an_image_asks_the_volume_for_nothing() {
    // The reason a cluster with an empty slot is stored plain: an image
    // occupies the whole cluster's worth of slots, so making one out of a
    // cluster that does not already hold them all would have to take room at
    // the placement. Every case that reaches an image therefore holds every
    // slot first, and this asserts the consequence — the count does not move.
    let (mut v, ino) = with_compressed();
    let before = v.valid_block_count;
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    assert_eq!(v.valid_block_count, before + CS as u64, "a slot went uncounted");
    v.sync_data().unwrap();
    assert_eq!(v.valid_block_count, before + CS as u64, "the placement counted a slot twice");
}

#[test]
fn a_full_volume_refuses_the_write_and_not_the_placement() {
    // ENOSPC belongs at the write, where the caller can still be told. Decide
    // it at the placement and the write below succeeds, the caller is told its
    // bytes are safe, and the flush fails with nobody left to report it to.
    let (mut v, ino) = with_compressed();
    leave_room_for(&mut v, 0);
    assert_eq!(v.write_file(ino, 0, &patterned(CS * BLKSIZE)), Err(Errno::Enospc));
    assert_eq!(v.dirty_data_pages(ino), 0, "a refused write still filed its pages");
    let a = addrs(&v, ino, 0);
    assert!(a.iter().all(|&x| x == NULL_ADDR), "a refused write still took a slot: {a:?}");
    assert_eq!(v.sync_data(), Ok(()), "the flush inherited the refusal");
}

#[test]
fn a_write_that_runs_out_part_way_reports_what_landed() {
    // Two blocks of room and a four-block cluster. What landed is the
    // caller's: reporting the whole write as refused would say the file is
    // unchanged when the next read returns two blocks of it.
    let (mut v, ino) = with_compressed();
    leave_room_for(&mut v, 2);
    let data = patterned(CS * BLKSIZE);
    assert_eq!(v.write_file(ino, 0, &data), Ok(2 * BLKSIZE));
    assert_eq!(v.read_inode(ino).unwrap().size, 2 * BLKSIZE as u64);
    v.sync_data().unwrap();
    assert_eq!(whole(&v, ino), data[..2 * BLKSIZE].to_vec());
}

#[test]
fn a_files_block_count_includes_the_slots_it_has_only_reserved() {
    // The count is what the file HOLDS, and a reservation is held space. A
    // count that waited for the addresses would report a file smaller than the
    // volume says it is between the write and the placement.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    let held = v.read_inode(ino).unwrap().blocks;
    assert!(held > CS as u64 - 1, "the reservations were not counted: {held}");
    v.sync_data().unwrap();
    assert_eq!(v.read_inode(ino).unwrap().blocks, held,
               "the placement changed what the file holds");
}

// ------------------------------------------------- an image is read-modified

#[test]
fn a_write_inside_an_image_dirties_the_whole_cluster() {
    // An image covers every block of its cluster, so changing one byte
    // rewrites all of them. Dirty only the block the write touched and the
    // placement compresses a cluster it has no bytes for.
    let (mut v, ino) = with_compressed();
    v.write_file(ino, 0, &patterned(CS * BLKSIZE)).unwrap();
    v.sync_data().unwrap();
    assert!(plan::compressed_extent(&addrs(&v, ino, 0)).is_some(), "the fixture has no image");
    v.write_file(ino, BLKSIZE as u64 + 17, b"the middle of the cluster").unwrap();
    assert_eq!(v.dirty_data_pages(ino), CS, "the write dirtied only its own block");
}

#[test]
fn a_write_inside_an_image_keeps_the_rest_of_it() {
    // The read-modify-write reads the cluster back before it patches. Skip
    // that read and the untouched blocks come back as zeroes.
    let (mut v, ino) = with_compressed();
    let mut want = patterned(CS * BLKSIZE);
    v.write_file(ino, 0, &want).unwrap();
    v.sync_data().unwrap();
    let patch = b"the middle of the cluster";
    let at = BLKSIZE as u64 + 17;
    v.write_file(ino, at, patch).unwrap();
    want[at as usize..at as usize + patch.len()].copy_from_slice(patch);
    v.sync_data().unwrap();
    assert_eq!(whole(&v, ino), want);
    assert_eq!(whole(&as_after_a_crash(&{ let mut v = v; v.commit().unwrap(); v }), ino), want);
}

#[test]
fn a_write_over_a_compressed_write_that_is_still_pending_keeps_both() {
    // The read-modify-write has to read the MAPPING, not the medium: a cluster
    // that has never been placed has no addresses to read back, so a writer
    // that went to the medium would lose the first write entirely.
    let (mut v, ino) = with_compressed();
    let mut want = patterned(CS * BLKSIZE);
    v.write_file(ino, 0, &want).unwrap();
    v.sync_data().unwrap();
    // Two writes into the same image, neither placed.
    v.write_file(ino, 5, b"AAAA").unwrap();
    v.write_file(ino, 2 * BLKSIZE as u64 + 9, b"BBBB").unwrap();
    want[5..9].copy_from_slice(b"AAAA");
    let at = 2 * BLKSIZE + 9;
    want[at..at + 4].copy_from_slice(b"BBBB");
    assert_eq!(whole(&v, ino), want, "before the placement");
    v.sync_data().unwrap();
    assert_eq!(whole(&v, ino), want, "after the placement");
}

// ----------------------------------------------------------- what still holds

#[test]
fn a_truncate_places_what_is_pending_before_it_reads_the_addresses() {
    // A truncate rearranges addresses, and a pending write has none. Take the
    // flush out of `truncate_compressed` and the cluster the new end falls
    // inside is rebuilt from the medium, which has never seen the write.
    let (mut v, ino) = with_compressed();
    let data = patterned(2 * CS * BLKSIZE);
    v.write_file(ino, 0, &data).unwrap();
    let len = 5 * BLKSIZE as u64 + 100;
    // The cluster truncater directly: `truncate_file` places pending pages on
    // its own way in, so a case going through it could not tell whether this
    // entry point does — and it is reachable on its own.
    v.truncate_compressed(ino, len).unwrap();
    assert_eq!(whole(&v, ino), data[..len as usize].to_vec());
}

#[test]
fn a_rewrite_command_places_what_is_pending_first() {
    // Both rewrite walks decide from the addresses, so a cluster whose blocks
    // are still reservations reads as one nothing can be made of. Take the
    // flush out of `rewrite_clusters` and this compresses nothing.
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut o = Options::defaults();
    o.compress.mode = crate::opts::CompressMode::User;
    let mut v = b.mount_opts(o).unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"c", &spec, None).unwrap();
    v.stamp_inode(ino, |blk| {
        let f = le32(blk, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(blk, I_FLAGS, f);
        blk[I_COMPRESS_ALGORITHM] = crate::compress::algo::COMPRESS_LZ4;
        blk[I_LOG_CLUSTER_SIZE] = LOG;
    })
    .unwrap();
    let data = patterned(CS * BLKSIZE);
    v.write_file(ino, 0, &data).unwrap();
    assert_eq!(v.compress_file(ino).unwrap(), 1, "the pending cluster was not seen");
    assert!(plan::compressed_extent(&addrs(&v, ino, 0)).is_some());
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn a_read_only_mount_takes_no_reservation() {
    let (mut v, ino) = with_compressed();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut ro = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                    Options::defaults(), false)
        .unwrap();
    assert_eq!(ro.write_file(ino, 0, &vec![1u8; BLKSIZE]), Err(Errno::Erofs));
    let a = addrs(&ro, ino, 0);
    assert!(a.iter().all(|&x| x == NULL_ADDR), "{a:?}");
}
