//! Every injectable site, reached through the operation that consults it.
//!
//! The site list is an ABI and the period algorithm has tests of its own. This
//! is the other half, and the half that was missing: whether a mount that asks
//! for a site to fail actually gets a failure out of the operation that owns
//! it. A site nothing consults is a bit a test can set and nothing can observe,
//! which is indistinguishable from a healthy filesystem.
//!
//! One site is armed per test, at a period of one, so the failure that arrives
//! can only have come from the site under test.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::fault::{Fault, Which};
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::quota_image as qi;
use crate::test_image::{self, nodes, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::quotas::USRQUOTA;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 0);
const UID: u32 = 4242;
const QUOTA_INO: u32 = 9;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: UID, gid: UID, rdev: 0, now: NOW }
}

fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// Arm exactly one site, failing every consultation of it.
fn arm(v: &Volume<MemImage>, f: Fault) {
    v.set_fault(1, 0, Which::RATE).unwrap();
    v.set_fault(0, f.bit(), Which::TYPE).unwrap();
}

#[test]
fn a_mount_that_named_a_rate_and_a_site_comes_up_with_that_site_armed() {
    let mut o = Options::defaults();
    o.fault.rate = Some(7);
    o.fault.types = Some(Fault::ReadIo.bit());
    let v = test_image::with_root().mount_opts(o).unwrap();
    assert_eq!(v.fault_info().rate(), 7, "the mount's rate never reached the volume");
    assert!(v.fault_info().armed(Fault::ReadIo), "the mount's site list never reached the volume");
}

#[test]
fn a_read_of_the_medium_can_be_made_to_fail() {
    let v = vol();
    arm(&v, Fault::ReadIo);
    assert_eq!(v.read_block(test_image::MAIN_BLKADDR), Err(Errno::Eio));
    assert_eq!(v.fault_info().count(Fault::ReadIo), 1, "the site did not count its failure");
}

#[test]
fn a_write_to_the_medium_can_be_made_to_fail() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    arm(&v, Fault::WriteIo);
    assert!(v.write_file(ino, 0, &vec![1u8; BLKSIZE]).is_err(), "the write went through");
}

#[test]
fn running_out_of_blocks_can_be_made_to_happen() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    arm(&v, Fault::Block);
    assert_eq!(v.write_file(ino, 0, &vec![1u8; BLKSIZE]), Err(Errno::Enospc));
}

#[test]
fn running_out_of_segments_can_be_made_to_happen() {
    let v = vol();
    assert!(v.find_free_seg(0).is_some(), "the fixture has no free segment to begin with");
    arm(&v, Fault::NoSegment);
    assert!(v.find_free_seg(0).is_none(), "a free segment was found anyway");
}

#[test]
fn running_out_of_node_ids_can_be_made_to_happen() {
    let mut v = vol();
    arm(&v, Fault::AllocNid);
    assert_eq!(v.alloc_nid(), Err(Errno::Enospc));
}

#[test]
fn parking_an_orphan_can_be_made_to_fail() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    arm(&v, Fault::Orphan);
    assert_eq!(v.add_orphan(ino), Err(Errno::Enospc));
}

#[test]
fn a_checkpoint_failure_stops_the_checkpoints_and_disarms_the_injection() {
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    arm(&v, Fault::Checkpoint);
    assert_eq!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0,
               "the fixture is already stopped");
    v.balance_fs(true).unwrap();
    assert_ne!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0,
               "the volume did not stop checkpointing");
    assert_eq!(v.fault_info().rate(), 0, "a stopped volume is still injecting");
}

#[test]
fn a_page_of_data_can_be_dropped_on_its_way_to_the_medium() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    // The reference arms this only while checkpoints are being re-enabled.
    v.sbi.begin_enable_checkpoint();
    arm(&v, Fault::SkipWrite);
    assert_eq!(v.write_file(ino, 0, &vec![1u8; BLKSIZE]), Err(Errno::Einval));
}

#[test]
fn shortening_a_file_can_be_made_to_fail() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    arm(&v, Fault::Truncate);
    assert_eq!(v.truncate_file(ino, 0), Err(Errno::Eio));
}

#[test]
fn evicting_an_inode_can_be_made_to_fail() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    arm(&v, Fault::EvictInode);
    assert_eq!(v.free_inode(ino), Err(Errno::Eio));
}

#[test]
fn a_directory_can_be_made_to_report_itself_too_deep() {
    let mut v = vol();
    // Only a directory whose entries live in blocks reaches the depth walk.
    v.convert_inline_dir(ROOT_INO).unwrap();
    arm(&v, Fault::DirDepth);
    assert_eq!(v.create(ROOT_INO, b"f", &spec(), None), Err(Errno::Enospc));
}

#[test]
fn an_address_check_can_be_made_to_refuse_a_good_address() {
    let v = vol();
    let addr = test_image::MAIN_BLKADDR;
    assert!(v.sb_main_contains(addr), "the fixture's own main area is not recognised");
    arm(&v, Fault::BlkaddrValidity);
    assert!(!v.sb_main_contains(addr), "the address check was not consulted");
}

#[test]
fn a_released_block_can_be_made_to_stay_live() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    let addr = v.holder_addr(ino, crate::volume::Holder::Inode, 0).unwrap();
    assert!(v.block_is_live(addr).unwrap(), "the block was never live");
    arm(&v, Fault::BlkaddrConsistence);
    v.release_slot(ino, addr).unwrap();
    assert!(v.block_is_live(addr).unwrap(),
            "the block was released, so the site was not consulted");
}

#[test]
fn a_node_footer_can_be_made_to_read_as_inconsistent() {
    let v = vol();
    assert!(v.read_node(ROOT_INO, Some(ROOT_INO)).is_ok(), "the fixture's root does not read");
    arm(&v, Fault::InconsistentFooter);
    assert_eq!(v.read_node(ROOT_INO, Some(ROOT_INO)).err(), Some(Errno::Eio));
}

#[test]
fn bringing_an_identitys_quota_record_in_can_be_made_to_fail() {
    let file = qi::user_file(UID, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = b.mount_opts(o).unwrap();
    assert!(v.quota_record(USRQUOTA, UID).is_ok(), "the fixture holds no record to withhold");
    arm(&v, Fault::DquotInit);
    assert_eq!(v.quota_record(USRQUOTA, UID), Err(Errno::Esrch));
}

/// The sites with no counterpart here, and why. Kept as a test so the list
/// cannot drift from the enum: a site added to the ABI is either wired or
/// named here.
#[test]
fn every_site_is_either_wired_or_named_as_having_no_counterpart() {
    let wired = [
        Fault::AllocNid, Fault::Orphan, Fault::Block, Fault::DirDepth, Fault::EvictInode,
        Fault::Truncate, Fault::ReadIo, Fault::Checkpoint, Fault::WriteIo, Fault::DquotInit,
        Fault::BlkaddrValidity, Fault::BlkaddrConsistence, Fault::NoSegment,
        Fault::InconsistentFooter, Fault::SkipWrite,
    ];
    // Six name a kernel memory allocator this filesystem does not own, two are
    // reserved by the ABI for requests that can no longer fail, one names a
    // filesystem-operation lock this design has no equivalent of, and two name
    // timeouts on waits that never happen here.
    let unwired = [
        Fault::Kmalloc, Fault::Kvmalloc, Fault::PageAlloc, Fault::PageGet, Fault::SlabAlloc,
        Fault::Vmalloc, Fault::AllocBio, Fault::Discard, Fault::LockOp, Fault::AtomicTimeout,
        Fault::LockTimeout,
    ];
    assert_eq!(wired.len() + unwired.len(), crate::fault::FAULT_MAX as usize,
               "a site was added to the ABI and neither wired nor accounted for");
    for i in 0..crate::fault::FAULT_MAX {
        let f = Fault::from_index(i).unwrap();
        assert!(wired.contains(&f) || unwired.contains(&f), "site {} is in neither list", f.name());
    }
}
