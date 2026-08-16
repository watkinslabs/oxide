//! Writing a file's bytes, and shortening one — proved by remounting.

use super::*;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{map::Mapped, NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume holding one empty file, and that file's number.
fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    (v, ino)
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

#[test]
fn a_short_write_stays_inside_the_inode() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"hello").unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert!(inode.inline_data());
    assert_eq!(inode.size, 5);
    assert_eq!(whole(&v, ino), b"hello".to_vec());
}

#[test]
fn a_write_at_an_offset_inside_the_inode_lands_where_it_was_put() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"aaaaaaaa").unwrap();
    v.write_file(ino, 3, b"XY").unwrap();
    let v = remount(v);
    assert_eq!(whole(&v, ino), b"aaaXYaaa".to_vec());
}

#[test]
fn a_write_past_the_inline_region_converts_the_file() {
    let (mut v, ino) = with_file();
    let region = v.read_inode(ino).unwrap().inline_data_span().1;
    let data = vec![0xABu8; region + 1];
    v.write_file(ino, 0, &data).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert!(!inode.inline_data());
    assert_eq!(inode.size, data.len() as u64);
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn converting_keeps_the_bytes_that_were_already_inline() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"keepme").unwrap();
    let region = v.read_inode(ino).unwrap().inline_data_span().1;
    v.write_file(ino, region as u64, b"tail").unwrap();
    let v = remount(v);
    let all = whole(&v, ino);
    assert_eq!(&all[..6], b"keepme");
    assert_eq!(&all[region..region + 4], b"tail");
}

#[test]
fn a_multi_block_write_reads_back_whole() {
    let (mut v, ino) = with_file();
    let data: Vec<u8> = (0..3 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    v.write_file(ino, 0, &data).unwrap();
    let v = remount(v);
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn a_write_spanning_a_block_boundary_lands_in_both() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    v.write_file(ino, BLKSIZE as u64 - 2, b"WXYZ").unwrap();
    let v = remount(v);
    let all = whole(&v, ino);
    assert_eq!(&all[BLKSIZE - 2..BLKSIZE + 2], b"WXYZ");
    assert_eq!(all[BLKSIZE - 3], 1);
    assert_eq!(all[BLKSIZE + 2], 1);
}

#[test]
fn a_write_past_the_end_leaves_a_hole_that_reads_as_zeroes() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![9u8; BLKSIZE]).unwrap();
    v.write_file(ino, 3 * BLKSIZE as u64, b"far").unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.size, 3 * BLKSIZE as u64 + 3);
    assert_eq!(v.map_block(&inode, ino, 1).unwrap(), Mapped::Hole);
    let all = whole(&v, ino);
    assert!(all[BLKSIZE..3 * BLKSIZE].iter().all(|&b| b == 0));
    assert_eq!(&all[3 * BLKSIZE..], b"far");
}

#[test]
fn rewriting_a_block_moves_it_and_releases_the_old_one() {
    // Out-of-place update is the whole design: the second write must land
    // somewhere else and give the first block back.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let Mapped::At(first) = v.map_block(&inode, ino, 0).unwrap() else { panic!("no block") };
    v.write_file(ino, 0, &vec![2u8; BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let Mapped::At(second) = v.map_block(&inode, ino, 0).unwrap() else { panic!("no block") };
    assert_ne!(first, second);
    assert!(!v.block_is_live(first).unwrap());
    assert!(v.block_is_live(second).unwrap());
}

#[test]
fn an_uncommitted_write_cannot_damage_the_last_committed_state() {
    // The reason updates are out of place: the previous checkpoint's blocks
    // must all still be intact until the next one retires them. An in-place
    // update would overwrite a block the committed checkpoint still points
    // at, and the crash would take the committed data with it.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![0xAAu8; 2 * BLKSIZE]).unwrap();
    v.commit().unwrap();
    v.write_file(ino, 0, &vec![0xBBu8; 2 * BLKSIZE]).unwrap();
    // No second commit: the medium must still describe the committed state.
    let bytes = v.into_source().snapshot();
    let v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                               Options::defaults(), true).unwrap();
    assert_eq!(whole(&v, ino), vec![0xAAu8; 2 * BLKSIZE]);
}

#[test]
fn overwriting_one_block_repeatedly_does_not_consume_the_volume() {
    // Every rewrite takes a fresh block; without the release the volume would
    // fill up rewriting one page.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let after_first = v.space().free;
    for i in 0..40u8 { v.write_file(ino, 0, &vec![i; BLKSIZE]).unwrap(); }
    v.commit().unwrap();
    let after_many = v.space().free;
    assert!(after_first.abs_diff(after_many) < 8,
            "forty rewrites cost {} blocks", after_first.abs_diff(after_many));
    assert_eq!(whole(&v, ino), vec![39u8; BLKSIZE]);
}

#[test]
fn a_write_reaching_a_direct_node_reads_back() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    // Force the conversion out of inline first, then write far out.
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.write_file(ino, apb * BLKSIZE as u64, b"direct").unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert!(matches!(v.map_block(&inode, ino, apb).unwrap(), Mapped::At(_)));
    let mut buf = [0u8; 6];
    v.read_file(&inode, ino, apb * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(&buf, b"direct");
}

#[test]
fn a_write_reaching_an_indirect_node_reads_back() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let index = apb + 2 * DEF_ADDRS_PER_BLOCK as u64;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.write_file(ino, index * BLKSIZE as u64, b"deep").unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = [0u8; 4];
    v.read_file(&inode, ino, index * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(&buf, b"deep");
}

#[test]
fn a_write_reaching_the_double_indirect_node_reads_back() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let p = NIDS_PER_BLOCK as u64;
    let index = apb + 2 * d + 2 * d * p;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.write_file(ino, index * BLKSIZE as u64, b"dind").unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = [0u8; 4];
    v.read_file(&inode, ino, index * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(&buf, b"dind");
}

#[test]
fn a_read_only_mount_refuses_to_write() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.write_file(ROOT_INO, 0, b"x").err(), Some(Errno::Erofs));
    assert_eq!(v.truncate_file(ROOT_INO, 0).err(), Some(Errno::Erofs));
}

#[test]
fn an_empty_write_changes_nothing() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"abc").unwrap();
    assert_eq!(v.write_file(ino, 99, b"").unwrap(), 3);
    assert_eq!(v.read_inode(ino).unwrap().size, 3);
}

#[test]
fn truncating_an_inline_file_shortens_it() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"abcdefgh").unwrap();
    v.truncate_file(ino, 3).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().size, 3);
    assert_eq!(whole(&v, ino), b"abc".to_vec());
}

#[test]
fn truncating_to_zero_leaves_an_empty_file() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![5u8; 2 * BLKSIZE]).unwrap();
    v.truncate_file(ino, 0).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().size, 0);
    assert!(whole(&v, ino).is_empty());
}

#[test]
fn truncating_releases_the_blocks_past_the_new_end() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![5u8; 3 * BLKSIZE]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let Mapped::At(gone) = v.map_block(&inode, ino, 2).unwrap() else { panic!("no block") };
    v.truncate_file(ino, BLKSIZE as u64).unwrap();
    assert!(!v.block_is_live(gone).unwrap());
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.map_block(&inode, ino, 2).unwrap(), Mapped::Hole);
}

#[test]
fn truncating_zeroes_the_tail_of_the_last_kept_block() {
    // The block is on the medium whole; a later write past the new end would
    // otherwise expose the bytes that were truncated away.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![0xEEu8; 2 * BLKSIZE]).unwrap();
    v.truncate_file(ino, BLKSIZE as u64 + 10).unwrap();
    v.truncate_file(ino, 2 * BLKSIZE as u64).unwrap();
    let v = remount(v);
    let all = whole(&v, ino);
    assert_eq!(all[BLKSIZE + 9], 0xEE);
    assert!(all[BLKSIZE + 10..].iter().all(|&b| b == 0), "tail was not cleared");
}

#[test]
fn truncating_frees_a_direct_node_whose_whole_range_is_gone() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.write_file(ino, apb * BLKSIZE as u64, b"x").unwrap();
    let nid = v.inode_slot(ino, 0).unwrap();
    assert_ne!(nid, 0);
    let node_addr = v.node_addr(nid).unwrap();
    v.truncate_file(ino, BLKSIZE as u64).unwrap();
    assert_eq!(v.inode_slot(ino, 0).unwrap(), 0, "the slot still names a freed node");
    assert!(!v.block_is_live(node_addr).unwrap(), "the node block leaked");
}

#[test]
fn truncating_keeps_a_node_that_still_covers_a_block() {
    let (mut v, ino) = with_file();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, apb * BLKSIZE as u64, b"keep").unwrap();
    v.write_file(ino, (apb + 5) * BLKSIZE as u64, b"drop").unwrap();
    v.truncate_file(ino, (apb + 1) * BLKSIZE as u64).unwrap();
    assert_ne!(v.inode_slot(ino, 0).unwrap(), 0);
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = [0u8; 4];
    v.read_file(&inode, ino, apb * BLKSIZE as u64, &mut buf).unwrap();
    assert_eq!(&buf, b"keep");
}

#[test]
fn extending_by_truncation_allocates_nothing() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let before = v.space().free;
    v.truncate_file(ino, 10 * BLKSIZE as u64).unwrap();
    v.commit().unwrap();
    assert_eq!(v.read_inode(ino).unwrap().size, 10 * BLKSIZE as u64);
    // Only the inode's own rewrite costs a block, not ten data blocks.
    assert!(before - v.space().free < 5);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.map_block(&inode, ino, 5).unwrap(), Mapped::Hole);
}

#[test]
fn a_files_block_count_tracks_what_it_occupies() {
    let (mut v, ino) = with_file();
    assert_eq!(v.read_inode(ino).unwrap().blocks, 1);
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    let v = remount(v);
    // The inode block plus its two data blocks.
    assert_eq!(v.read_inode(ino).unwrap().blocks, 3);
}

#[test]
fn writing_to_a_compressed_inode_is_refused_rather_than_corrupting_it() {
    let (mut v, ino) = with_file();
    v.stamp_inode(ino, |b| {
        b[I_FLAGS..I_FLAGS + 4].copy_from_slice(&crate::flags::F2FS_COMPR_FL.to_le_bytes())
    })
    .unwrap();
    assert_eq!(v.write_file(ino, 0, b"x").err(), Some(Errno::Eopnotsupp));
}

#[test]
fn a_written_file_is_still_reachable_by_name_after_a_remount() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"payload").unwrap();
    let v = remount(v);
    let root = v.root().unwrap();
    let hit = v.lookup(&root, ROOT_INO, b"f").unwrap();
    assert_eq!(hit.ino, ino);
    assert_eq!(whole(&v, hit.ino), b"payload".to_vec());
}
