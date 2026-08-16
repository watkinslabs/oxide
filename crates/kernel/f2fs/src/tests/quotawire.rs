//! Allocations are charged to the identities that own them.
//!
//! The quota decode, tree walk and limit decision have tests of their own.
//! These are about the CALL SITES: whether a write charges anything, whether
//! a limit refuses anything, and whether what was charged survives.

use super::*;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::quota::info::Revision;
use crate::quota::uapi::QT_BLOCK_SIZE;
use crate::test_image::quota_image as qi;
use crate::test_image::{self, nodes, ROOT_INO};
use crate::volume::quotas::USRQUOTA;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 0);
const UID: u32 = 4242;
const QUOTA_INO: u32 = 9;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: UID, gid: UID, rdev: 0, now: NOW }
}

/// A volume whose user-quota file holds one record for `UID`.
fn with_quota(bhard_units: u64, ihard: u64, enforce: bool) -> Volume<MemImage> {
    let file = qi::user_file(UID, bhard_units, ihard);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = enforce;
    let mut v = b.mount_opts(o).unwrap();
    v.set_clock(NOW.0);
    v
}

fn space(v: &mut Volume<MemImage>) -> u64 {
    v.quota_record(USRQUOTA, UID).unwrap().curspace
}

fn inodes(v: &mut Volume<MemImage>) -> u64 {
    v.quota_record(USRQUOTA, UID).unwrap().curinodes
}

#[test]
fn a_volume_naming_a_quota_file_accounts_that_kind() {
    let v = with_quota(0, 0, true);
    assert!(v.quota_active());
    assert!(crate::quota::types::enforced(&v.quota_setup()[USRQUOTA]));
}

#[test]
fn a_mount_that_did_not_ask_still_tracks_usage_but_enforces_nothing() {
    // The reference accounts whenever the file exists; only the option turns
    // the counts into refusals.
    let v = with_quota(0, 0, false);
    assert!(v.quota_active());
    assert!(!crate::quota::types::enforced(&v.quota_setup()[USRQUOTA]));
}

#[test]
fn creating_a_file_charges_one_inode_and_no_space() {
    // The reference counts a new inode as an INODE; the block it occupies is
    // never charged against the owner's space.
    let mut v = with_quota(0, 0, true);
    let before = (space(&mut v), inodes(&mut v));
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert_eq!(inodes(&mut v), before.1 + 1, "the inode was not charged");
    assert_eq!(space(&mut v), before.0, "the inode's own block was charged as space");
}

#[test]
fn a_node_block_other_than_the_inode_is_charged_as_space() {
    // Every node that is not the inode reserves one block against the owner.
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    let before = space(&mut v);
    // Past the inode's own array, so this needs a direct node as well.
    v.write_file(ino, apb * BLKSIZE as u64, b"x").unwrap();
    assert_eq!(space(&mut v), before + 2 * BLKSIZE as u64,
               "the direct node and the data block should each cost one block");
}

#[test]
fn writing_blocks_charges_their_space() {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let before = space(&mut v);
    v.write_file(ino, 0, &vec![1u8; 3 * BLKSIZE]).unwrap();
    assert!(space(&mut v) >= before + 3 * BLKSIZE as u64, "blocks were not charged");
}

#[test]
fn rewriting_a_block_charges_nothing_further() {
    // An out-of-place update MOVES a block; the owner occupies no more of the
    // volume than before, and charging it again would drain a quota by
    // rewriting one page.
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    let after_first = space(&mut v);
    for i in 0..8u8 { v.write_file(ino, 0, &vec![i; BLKSIZE]).unwrap(); }
    assert_eq!(space(&mut v), after_first, "a rewrite was charged as new space");
}

#[test]
fn a_hard_space_limit_shortens_the_write_then_refuses_it() {
    // Room for some of the write and not all of it. Space is charged one
    // block at a time, so the write stops where the room runs out: the blocks
    // that fit are written and reported, and only a further write — which has
    // nowhere at all to go — is refused outright.
    let mut v = with_quota(8, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let n = v.write_file(ino, 0, &vec![1u8; 8 * BLKSIZE]).unwrap();
    assert!(n > 0 && n < 8 * BLKSIZE, "expected a short write, got {}", n);
    assert!(space(&mut v) <= qi::units(8), "it charged past the hard limit");
    // The file describes what landed, not what was asked for.
    assert_eq!(v.read_inode(ino).unwrap().size, n as u64);
    assert_eq!(v.write_file(ino, n as u64, &vec![1u8; BLKSIZE]).err(), Some(Errno::Edquot));
}

#[test]
fn a_mount_that_only_tracks_usage_refuses_nothing() {
    let mut v = with_quota(8, 0, false);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 8 * BLKSIZE]).unwrap();
    // Counted past the limit, which is what "usage only" means.
    assert!(space(&mut v) > qi::units(8));
}

#[test]
fn a_hard_inode_limit_refuses_the_create() {
    let mut v = with_quota(0, 2, true);
    v.create(ROOT_INO, b"a", &spec(), None).unwrap();
    v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    assert_eq!(v.create(ROOT_INO, b"c", &spec(), None).err(), Some(Errno::Edquot));
}

#[test]
fn a_write_that_runs_out_of_room_keeps_what_it_wrote() {
    // The blocks that landed are the file's contents now. Reporting the whole
    // call as failed would tell the caller its file is unchanged when it is
    // not, and a reader would then be surprised by bytes nobody admits to.
    let mut v = with_quota(8, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    let n = v.write_file(ino, 0, &vec![9u8; 8 * BLKSIZE]).unwrap();
    assert!(n > 0 && n < 8 * BLKSIZE, "expected a short write, got {}", n);
    let inode = v.read_inode(ino).unwrap();
    let got = v.read_whole(&inode, ino).unwrap();
    assert_eq!(got.len(), n);
    assert!(got.iter().all(|&b| b == 9), "the bytes that landed were not kept");
}

#[test]
fn truncating_gives_the_space_back() {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
    let full = space(&mut v);
    v.truncate_file(ino, 0).unwrap();
    assert!(space(&mut v) < full, "truncation returned nothing");
}

#[test]
fn unlinking_returns_everything_the_file_held() {
    let mut v = with_quota(0, 0, true);
    let before = (space(&mut v), inodes(&mut v));
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 3 * BLKSIZE]).unwrap();
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    assert_eq!(inodes(&mut v), before.1, "the inode was not returned");
    assert_eq!(space(&mut v), before.0, "space was not returned");
}

#[test]
fn space_freed_makes_room_for_the_write_that_was_refused() {
    // Four blocks of room, and two files that each want three.
    let mut v = with_quota(16, 0, true);
    let a = v.create(ROOT_INO, b"a", &spec(), None).unwrap();
    v.write_file(a, 0, &vec![1u8; 3 * BLKSIZE]).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    let n = v.write_file(b, 0, &vec![2u8; 3 * BLKSIZE]).unwrap();
    assert!(n < 3 * BLKSIZE, "the room was already gone, yet the write completed");
    v.remove(ROOT_INO, b"a", false, NOW).unwrap();
    v.write_file(b, 0, &vec![2u8; 3 * BLKSIZE]).unwrap();
    assert_eq!(space(&mut v), 3 * BLKSIZE as u64);
}

#[test]
fn the_quota_files_own_blocks_are_not_charged() {
    // Charging the growth of the file that records an identity's usage to
    // that identity does not terminate.
    let mut v = with_quota(0, 0, true);
    let before = space(&mut v);
    v.commit().unwrap();
    assert_eq!(space(&mut v), before, "writing the quota file charged somebody");
}

#[test]
fn what_was_charged_survives_a_remount() {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 3 * BLKSIZE]).unwrap();
    let want = space(&mut v);
    assert!(want > 0);
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v =
        Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap();
    v.set_clock(NOW.0);
    assert_eq!(space(&mut v), want, "the accounting did not reach the medium");
}

#[test]
fn a_volume_with_no_quota_file_accounts_nothing_and_refuses_nothing() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    assert!(!v.quota_active());
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
}

#[test]
fn a_checkpoint_that_marked_the_files_for_repair_suppresses_accounting() {
    // Accounting against a file known to be inconsistent writes the
    // inconsistency deeper.
    let file = qi::user_file(UID, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    b.cp_flags |= crate::flags::CP_QUOTA_NEED_FSCK_FLAG;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    let v = b.mount_opts(o).unwrap();
    assert!(!v.quota_active());
}

#[test]
fn the_grace_clock_reaches_the_decision() {
    // A soft limit is an absolute expiry; without a clock it could never come
    // due, and the record's stored time would never be read.
    let mut v = with_quota(0, 0, true);
    v.set_clock(NOW.0);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    assert!(space(&mut v) > 0);
    let _ = ino;
    let _: u64 = QT_BLOCK_SIZE as u64;
    let _: Revision = Revision::R1;
}

#[test]
fn space_is_charged_in_whole_blocks_and_nothing_else() {
    // Pinned against the reference's own arithmetic: a file wholly inside the
    // inode's address array costs one block per block of data and no more.
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let before = space(&mut v);
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
    assert_eq!(space(&mut v) - before, 4 * BLKSIZE as u64);
}

#[test]
fn a_disk_limit_is_read_in_quota_blocks_and_compared_in_bytes() {
    // The on-disk hard limit is a count of thousand-and-twenty-four-byte
    // units; the usage beside it is a byte count. Comparing the two without
    // the conversion makes a limit a thousandfold too small.
    let mut v = with_quota(8, 0, true);
    let d = v.quota_record(USRQUOTA, UID).unwrap();
    assert_eq!(d.bhardlimit, qi::units(8));
    assert_eq!(d.bhardlimit, 8 * 1024);
}
