//! A file that stands for a whole member device.

use alloc::vec::Vec;

use crate::devices::alias::{self, AliasError};
use crate::devices::DevTable;
use crate::flags::{F2FS_DEVICE_ALIAS_FL, FEATURE_DEVICE_ALIAS, PIN_FILE};
use crate::node::Inode;
use crate::sb::SuperBlock;
use crate::test_image as image;
use crate::test_image::nodes::{inode_block, Spec};
use crate::uapi::{I_EXT_BLK, I_EXT_FOFS, I_EXT_LEN, SUPER_OFFSET, SUPER_SIZE};

const FEATURE: u32 = image::DEFAULT_FEATURE | FEATURE_DEVICE_ALIAS;

fn sb() -> SuperBlock {
    let bytes = image::Builder::new()
        .devices(&[("/dev/a", 8), ("/dev/b", 7)])
        .finish();
    crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).expect("parses")
}

fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }

/// An inode whose cached extent is `blk..blk+len`, aliasing when `alias` and
/// pinned when `pinned`.
fn inode(blk: u32, len: u32, alias_flag: bool, pinned: bool) -> Inode {
    let mut s = Spec::file(9);
    if alias_flag { s.flags |= F2FS_DEVICE_ALIAS_FL; }
    if pinned { s.inline |= PIN_FILE; }
    let mut b = inode_block(&s);
    put32(&mut b, I_EXT_FOFS, 0);
    put32(&mut b, I_EXT_BLK, blk);
    put32(&mut b, I_EXT_LEN, len);
    crate::node::inode::parse(&b, FEATURE).expect("inode parses")
}

/// The span of member `i`, as an extent.
fn span(t: &DevTable, i: usize) -> (u32, u32) {
    let d = t.get(i).unwrap();
    (d.start_blk, d.end_blk - d.start_blk + 1)
}

fn no_zones(_: usize) -> bool { false }

#[test]
fn only_the_high_flag_marks_an_alias() {
    assert!(alias::is_alias(F2FS_DEVICE_ALIAS_FL));
    assert!(!alias::is_alias(0));
    assert!(!alias::is_alias(F2FS_DEVICE_ALIAS_FL >> 1));
}

#[test]
fn an_extent_covering_a_whole_member_names_it() {
    let s = sb();
    let t = DevTable::scan(&s);
    let (blk, len) = span(&t, 1);
    let i = inode(blk, len, true, true);
    assert_eq!(alias::resolve(&i, FEATURE, true, &t, no_zones), Ok(1));
}

#[test]
fn an_extent_one_block_short_of_a_member_names_none() {
    let s = sb();
    let t = DevTable::scan(&s);
    let (blk, len) = span(&t, 1);
    let i = inode(blk, len - 1, true, true);
    assert_eq!(alias::resolve(&i, FEATURE, true, &t, no_zones), Err(AliasError::NoSuchDevice));
}

#[test]
fn the_first_member_may_not_be_aliased() {
    // It holds the superblock and the checkpoint; handing it out hands out
    // the filesystem's own metadata.
    let s = sb();
    let t = DevTable::scan(&s);
    let (blk, len) = span(&t, 0);
    let i = inode(blk, len, true, true);
    assert_eq!(alias::resolve(&i, FEATURE, true, &t, no_zones), Err(AliasError::MetaDevice));
}

#[test]
fn a_zoned_member_may_not_be_aliased() {
    let s = sb();
    let t = DevTable::scan(&s);
    let (blk, len) = span(&t, 1);
    let i = inode(blk, len, true, true);
    assert_eq!(alias::resolve(&i, FEATURE, true, &t, |d| d == 1), Err(AliasError::Zoned));
}

#[test]
fn an_unpinned_alias_is_refused() {
    // The cleaner would move it, and the member's blocks would then be
    // somewhere else while the file still claims the span.
    let s = sb();
    let t = DevTable::scan(&s);
    let (blk, len) = span(&t, 1);
    let i = inode(blk, len, true, false);
    assert_eq!(alias::resolve(&i, FEATURE, false, &t, no_zones), Err(AliasError::NotPinned));
}

#[test]
fn the_flag_means_nothing_without_the_feature() {
    let s = sb();
    let t = DevTable::scan(&s);
    let (blk, len) = span(&t, 1);
    let i = inode(blk, len, true, true);
    assert_eq!(
        alias::resolve(&i, image::DEFAULT_FEATURE, true, &t, no_zones),
        Err(AliasError::FeatureOff));
}

#[test]
fn an_empty_extent_names_no_member() {
    let s = sb();
    let t = DevTable::scan(&s);
    let i = inode(0, 0, true, true);
    assert_eq!(alias::resolve(&i, FEATURE, true, &t, no_zones), Err(AliasError::NoSuchDevice));
}

#[test]
fn the_flag_check_passes_every_ordinary_inode() {
    for feature in [0u32, FEATURE_DEVICE_ALIAS] {
        for pinned in [false, true] {
            assert!(alias::flag_ok(0, feature, pinned));
        }
    }
}

#[test]
fn the_flag_check_needs_both_the_feature_and_the_pin() {
    assert!(alias::flag_ok(F2FS_DEVICE_ALIAS_FL, FEATURE_DEVICE_ALIAS, true));
    assert!(!alias::flag_ok(F2FS_DEVICE_ALIAS_FL, FEATURE_DEVICE_ALIAS, false));
    assert!(!alias::flag_ok(F2FS_DEVICE_ALIAS_FL, 0, true));
}

#[test]
fn every_later_member_is_reachable_as_an_alias() {
    let bytes = image::Builder::new()
        .devices(&[("/dev/a", 8), ("/dev/b", 4), ("/dev/c", 3)])
        .finish();
    let s = crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).unwrap();
    let t = DevTable::scan(&s);
    let found: Vec<usize> = (1..t.len())
        .map(|i| {
            let (blk, len) = span(&t, i);
            alias::resolve(&inode(blk, len, true, true), FEATURE, true, &t, no_zones).unwrap()
        })
        .collect();
    assert_eq!(found, alloc::vec![1, 2]);
}
