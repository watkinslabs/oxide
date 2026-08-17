//! A whole volume, read end to end from an image built byte by byte.
//!
//! Module manifest:
//! - `read`:  file bytes: inline, blocked, sparse, deep and symbolic.
//! - `dirs`:  finding a name and listing a directory.
//! - `space`: `statfs`, the segment table, and attribute regions.
//! - `encrypted`: an encrypted directory, locked and unlocked.
//! - `inlinecrypt`: the mount option that moves contents encryption down a
//!                  layer, and the proof the medium is unchanged by it.

use super::*;
use crate::features::Access;
use crate::flags::*;
use crate::test_image::{self, nodes, Builder, ROOT_INO};
use crate::uapi::*;
use syscall::errno::Errno;

#[path = "volume/read.rs"]
mod read;
#[path = "volume/dirs.rs"]
mod dirs;
#[path = "volume/space.rs"]
mod space;
#[path = "volume/reserve_gate.rs"]
mod reserve_gate;
#[path = "volume/encrypted.rs"]
mod encrypted;
#[path = "volume/inlinecrypt.rs"]
mod inlinecrypt;

#[test]
fn a_fixture_volume_mounts() {
    let v = test_image::with_root().mount().unwrap();
    assert_eq!(v.root_ino(), ROOT_INO);
    assert_eq!(v.super_block().segment_count, test_image::SEGMENT_COUNT);
}

#[test]
fn a_mount_that_did_not_ask_to_write_is_not_writable() {
    let v = test_image::with_root().mount().unwrap();
    assert!(!v.writable());
}

#[test]
fn a_mount_asking_to_write_a_plain_volume_gets_it() {
    let b = test_image::with_root();
    let v = Volume::mount_with(b.image(), crate::opts::Options::defaults(), true).unwrap();
    assert_eq!(v.access(), Access::ReadWrite);
    assert!(v.writable());
}

#[test]
fn a_volume_marked_read_only_mounts_read_only_even_when_write_was_asked() {
    let mut b = test_image::with_root();
    b.feature |= FEATURE_RO;
    let v = Volume::mount_with(b.image(), crate::opts::Options::defaults(), true).unwrap();
    assert_eq!(v.access(), Access::ReadOnly);
    assert!(!v.writable());
}

#[test]
fn an_unrecognised_feature_bit_still_mounts() {
    // Matching the reference: the feature word is not an incompatibility mask.
    let mut b = test_image::with_root();
    b.feature |= 1 << 22;
    let v = b.mount().unwrap();
    assert_eq!(v.root_ino(), ROOT_INO);
}

#[test]
fn a_case_folding_volume_refuses_the_mount() {
    let mut b = test_image::with_root();
    b.feature |= FEATURE_CASEFOLD;
    assert_eq!(b.mount().err(), Some(Errno::Einval));
}

#[test]
fn a_broken_first_superblock_falls_back_to_the_second() {
    let mut b = test_image::with_root();
    b.break_super0 = true;
    let v = b.mount().unwrap();
    assert_eq!(v.root_ino(), ROOT_INO);
}

#[test]
fn a_volume_with_neither_superblock_valid_refuses() {
    let mut bytes = test_image::with_root().finish();
    for copy in 0..SUPER_COPIES as usize {
        let at = copy * BLKSIZE + SUPER_OFFSET + SB_MAGIC;
        bytes[at] ^= 0xFF;
    }
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    assert!(Volume::mount_with(img, crate::opts::Options::defaults(), false).is_err());
}

#[test]
fn a_superblock_whose_checksum_is_wrong_refuses() {
    let mut bytes = test_image::with_root().finish();
    for copy in 0..SUPER_COPIES as usize {
        let at = copy * BLKSIZE + SUPER_OFFSET + SB_SEGMENT_COUNT;
        bytes[at] ^= 0xFF;
    }
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    assert!(Volume::mount_with(img, crate::opts::Options::defaults(), false).is_err());
}

#[test]
fn the_newer_checkpoint_pack_is_the_one_mounted() {
    let mut b = test_image::with_root();
    b.cp_version = 4;
    b.cp2_version = Some(9);
    let v = b.mount().unwrap();
    assert_eq!(v.checkpoint().version, 9);
    assert_eq!(v.checkpoint().pack, crate::checkpoint::Pack::Second);
}

#[test]
fn the_first_pack_is_taken_when_it_is_the_newer() {
    let mut b = test_image::with_root();
    b.cp_version = 9;
    b.cp2_version = Some(4);
    let v = b.mount().unwrap();
    assert_eq!(v.checkpoint().version, 9);
    assert_eq!(v.checkpoint().pack, crate::checkpoint::Pack::First);
}

#[test]
fn a_torn_pack_is_ignored_in_favour_of_the_other() {
    // Break the FIRST pack's tail so its head and tail disagree.
    let mut b = test_image::with_root();
    b.cp_version = 9;
    b.cp2_version = Some(4);
    let mut bytes = b.finish();
    let tail = (test_image::CP_BLKADDR + test_image::CP_PACK_BLOCKS - 1) as usize * BLKSIZE;
    bytes[tail + CP_CHECKPOINT_VER] ^= 0xFF;
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, crate::opts::Options::defaults(), false).unwrap();
    assert_eq!(v.checkpoint().version, 4);
}

#[test]
fn a_volume_with_both_packs_broken_refuses() {
    let mut bytes = test_image::with_root().finish();
    for pack in 0..2u32 {
        let head = (test_image::CP_BLKADDR + pack * BLKS_PER_SEG) as usize * BLKSIZE;
        bytes[head + CP_VALID_NODE_COUNT] ^= 0xFF;
    }
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    assert!(Volume::mount_with(img, crate::opts::Options::defaults(), false).is_err());
}

#[test]
fn a_pack_with_a_bad_checkpoint_checksum_is_not_used() {
    let mut b = test_image::with_root();
    b.cp_version = 9;
    b.cp2_version = Some(4);
    let mut bytes = b.finish();
    let head = test_image::CP_BLKADDR as usize * BLKSIZE;
    bytes[head + CP_FREE_SEGMENT_COUNT] ^= 0xFF;
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, crate::opts::Options::defaults(), false).unwrap();
    assert_eq!(v.checkpoint().version, 4);
}

#[test]
fn the_large_bitmap_layout_mounts_and_reads() {
    // The bitmaps move by four bytes and swap order; a reader ignoring the
    // flag selects the other copy of every table block.
    let mut b = Builder::new().cp_flags(CP_UMOUNT_FLAG | CP_LARGE_NAT_BITMAP_FLAG);
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    let v = b.mount().unwrap();
    assert!(v.checkpoint().has(CP_LARGE_NAT_BITMAP_FLAG));
    assert_eq!(v.root().unwrap().mode & crate::mode::S_IFMT, crate::mode::S_IFDIR);
}

#[test]
fn a_compact_summary_pack_finds_its_journals() {
    let mut b = Builder::new().cp_flags(CP_UMOUNT_FLAG | CP_COMPACT_SUM_FLAG);
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    let v = b.mount().unwrap();
    assert!(v.root().is_ok());
}

#[test]
fn a_pack_written_without_node_summaries_finds_its_journals() {
    // The summary blocks sit three blocks further on; the wrong base reads a
    // block that is not a journal at all.
    let mut b = Builder::new().cp_flags(0);
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    let v = b.mount().unwrap();
    assert!(!v.checkpoint().node_summaries_present());
    assert!(v.root().is_ok());
}

#[test]
fn the_root_inode_reads_back_as_a_directory() {
    let v = test_image::with_root().mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(root.mode & crate::mode::S_IFMT, crate::mode::S_IFDIR);
    assert!(root.inline_dentry());
    assert_eq!(root.links, 2);
}

#[test]
fn a_node_id_outside_the_tables_range_is_refused() {
    let v = test_image::with_root().mount().unwrap();
    assert_eq!(v.node_addr(0), Err(Errno::Einval));
    assert_eq!(v.node_addr(v.max_nid()), Err(Errno::Einval));
    assert!(v.node_addr(v.max_nid() - 1).is_ok());
}

#[test]
fn the_node_table_answers_the_address_the_fixture_recorded() {
    let mut b = test_image::with_root();
    let s = nodes::add_inline_file(&mut b, 4, b"hi");
    let want = b.nat.iter().find(|(n, _)| *n == s.ino).unwrap().1.block_addr;
    let v = b.mount().unwrap();
    assert_eq!(v.node_addr(4).unwrap(), want);
}

#[test]
fn a_journalled_node_entry_overrides_the_table() {
    // The fixture writes a STALE table copy pointing one block earlier; a
    // reader ignoring the journal reads that and gets another node's block.
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"table copy");
    let table_addr = b.nat.iter().find(|(n, _)| *n == 4).unwrap().1.block_addr;
    let fresh = nodes::add_inline_file(&mut b, 5, b"journal copy");
    let fresh_addr = b.nat.iter().find(|(n, _)| *n == fresh.ino).unwrap().1.block_addr;
    b.journal_nid(4, 4, fresh_addr);
    let v = b.mount().unwrap();
    assert_ne!(table_addr, fresh_addr);
    assert_eq!(v.node_addr(4).unwrap(), fresh_addr);
}

#[test]
fn the_version_bitmap_selects_the_second_table_copy() {
    // With the bit set the fixture writes the live entries into the SECOND
    // copy and a stale set into the first.
    let mut b = test_image::with_root();
    b.nat_bitmap[0] |= 1;
    nodes::add_inline_file(&mut b, 4, b"hello");
    let want = b.nat.iter().find(|(n, _)| *n == 4).unwrap().1.block_addr;
    let v = b.mount().unwrap();
    assert_eq!(v.node_addr(4).unwrap(), want);
    let (inode, _) = v.read_inode_ref(4).unwrap();
    assert_eq!(inode.size, 5);
}

#[test]
fn a_node_block_whose_footer_names_another_node_is_refused() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"hi");
    let addr = b.nat.iter().find(|(n, _)| *n == 4).unwrap().1.block_addr;
    let mut bytes = b.finish();
    let at = addr as usize * BLKSIZE + NODE_FOOTER_OFF + FOOTER_NID;
    bytes[at..at + 4].copy_from_slice(&99u32.to_le_bytes());
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, crate::opts::Options::defaults(), false).unwrap();
    assert_eq!(v.read_inode(4).err(), Some(Errno::Eio));
}

#[test]
fn an_inode_whose_checksum_does_not_match_is_refused() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"hi");
    let addr = b.nat.iter().find(|(n, _)| *n == 4).unwrap().1.block_addr;
    let mut bytes = b.finish();
    bytes[addr as usize * BLKSIZE + I_SIZE] ^= 0xFF;
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, crate::opts::Options::defaults(), false).unwrap();
    assert_eq!(v.read_inode(4).err(), Some(Errno::Eio));
}

#[test]
fn a_block_outside_the_main_area_is_refused() {
    let v = test_image::with_root().mount().unwrap();
    assert!(v.read_main_block(test_image::MAIN_BLKADDR).is_ok());
    assert_eq!(v.read_main_block(test_image::MAIN_BLKADDR - 1).err(), Some(Errno::Eio));
    assert_eq!(v.read_main_block(0).err(), Some(Errno::Eio));
}

#[test]
fn a_block_past_the_volume_is_refused_rather_than_read_short() {
    let v = test_image::with_root().mount().unwrap();
    assert_eq!(v.read_block(u32::try_from(test_image::BLOCK_COUNT).unwrap()).err(),
               Some(Errno::Eio));
}
