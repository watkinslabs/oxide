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
    // Through the flush, because a buffered write reaches no medium: the page
    // and the node it changes are both placed later, which is the one point
    // the site can fail at.
    let out = v.write_file(ino, 0, &vec![1u8; BLKSIZE]).and_then(|_| v.sync_data());
    assert!(out.is_err(), "the write went through");
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
    // The site is on the way to the MEDIUM, which a buffered write reaches at
    // writeback: the write itself only takes the room and files the page.
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    assert_eq!(v.sync_data(), Err(Errno::Einval));
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
    v.sync_data().unwrap();
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
    // The site is the ACQUISITION an operation does before it allocates, which
    // is the one place records are brought in. Reporting a record a caller
    // asked for by name is not that site and is left alone.
    arm(&v, Fault::DquotInit);
    assert_eq!(v.dquot_initialize(ROOT_INO), Err(Errno::Esrch));
    assert!(v.quota_record(USRQUOTA, UID).is_ok());
}

#[test]
fn loading_the_segment_table_can_be_made_to_fail() {
    // The table is one entry per main segment, taken whole, and it is the
    // largest allocation the size of the volume decides. A mount that has not
    // needed it yet is the only place the site can be reached, which is why
    // this arms before anything asks for it.
    let mut v = test_image::with_root().mount_rw().unwrap();
    arm(&v, Fault::Kvmalloc);
    assert_eq!(v.load_segments(), Err(Errno::Enomem));
    assert_eq!(v.fault_info().count(Fault::Kvmalloc), 1, "the site did not count its failure");
}

#[test]
fn assembling_an_inodes_attribute_region_can_be_made_to_fail() {
    let v = vol();
    let inode = v.read_inode(ROOT_INO).unwrap();
    assert!(v.xattr_area(&inode, ROOT_INO).is_ok(), "the fixture's own region does not assemble");
    arm(&v, Fault::Kmalloc);
    assert_eq!(v.xattr_area(&inode, ROOT_INO), Err(Errno::Enomem));
}

#[test]
fn grabbing_a_page_to_write_into_can_be_made_to_fail() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    // A whole block first, so the file's bytes live in a BLOCK. A small file
    // stays inside its inode, and an inline write never grabs a page at all.
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    arm(&v, Fault::PageAlloc);
    // A part-block write is the one that has to hold the page before it can
    // patch it, which is where a page is grabbed for writing.
    assert_eq!(v.write_file(ino, 0, &[7u8; 100]), Err(Errno::Enomem));
    // And the file's bytes are exactly as they were.
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; BLKSIZE];
    v.read_file(&inode, ino, 0, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 1), "the refused write changed the file");
}

#[test]
fn looking_a_page_up_in_the_file_mapping_can_be_made_to_fail() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![3u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let addr = v.holder_addr(ino, crate::volume::Holder::Inode, 0).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert!(v.read_data_page(&inode, ino, 0, addr, None).is_ok(), "the fixture's page does not read");
    arm(&v, Fault::PageGet);
    assert_eq!(v.read_data_page(&inode, ino, 0, addr, None), Err(Errno::Enomem));
}

#[test]
fn looking_a_sealed_files_page_up_can_be_made_to_fail_too() {
    // The sibling of the test above, and not redundant with it. A sealed file
    // is read by a DIFFERENT function — the attestation is a separate reader
    // so that the tree climb stays out of the read half of a read-modify-write
    // — and a site wired into only the ordinary one fires for an ordinary file
    // and not for a sealed one, which is worse than not having it. Deleting
    // either injection leaves one of these two red.
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![3u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.enable_verity(ino, crate::verity::uapi::HASH_ALG_SHA256, 12, b"").unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert!(inode.verity(), "the fixture is not sealed, so it reads by the other path");
    v.verity_file_open(&inode, ino, false).unwrap();
    let addr = v.holder_addr(ino, crate::volume::Holder::Inode, 0).unwrap();
    v.data_cache.forget_inode(ino);
    assert!(v.read_data_page(&inode, ino, 0, addr, None).is_ok(),
            "the fixture's page does not read");
    v.data_cache.forget_inode(ino);
    arm(&v, Fault::PageGet);
    assert_eq!(v.read_data_page(&inode, ino, 0, addr, None), Err(Errno::Enomem));
}

#[test]
fn taking_an_inode_record_can_be_made_to_fail() {
    let mut v = vol();
    arm(&v, Fault::SlabAlloc);
    assert_eq!(v.create(ROOT_INO, b"f", &spec(), None), Err(Errno::Enomem));
    // Nothing was handed out: the site fires before the node id is taken, so
    // the name is simply absent rather than half-created.
    let root = v.read_inode(ROOT_INO).unwrap();
    assert!(v.lookup(&root, ROOT_INO, b"f").is_err(), "a name was left behind");
}

#[test]
fn unpacking_a_compressed_cluster_can_be_made_to_fail() {
    // The buffer a cluster unpacks into is the largest single allocation any
    // read makes, and the only one this filesystem would take from the virtual
    // allocator.
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    v.stamp_inode(ino, |blk| {
        let f = crate::uapi::le32(blk, crate::uapi::I_FLAGS).unwrap_or(0)
            | crate::flags::F2FS_COMPR_FL;
        crate::volume::dnode::put32(blk, crate::uapi::I_FLAGS, f);
        blk[crate::uapi::I_COMPRESS_ALGORITHM] = crate::compress::algo::COMPRESS_LZ4;
        blk[crate::uapi::I_LOG_CLUSTER_SIZE] = 2;
    })
    .unwrap();
    // Compressible bytes, or the cluster is stored plain and never unpacked.
    let data = vec![0x5Au8; 8 * BLKSIZE];
    v.write_compressed(ino, 0, &data).unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let v = Volume::mount_with(sectors::MemImage::from_bytes(BLKSIZE as u32, bytes),
                               Options::defaults(), true).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 64];
    assert!(v.read_file(&inode, ino, 7, &mut buf).is_ok(), "the fixture's cluster does not read");
    arm(&v, Fault::Vmalloc);
    assert_eq!(v.read_file(&inode, ino, BLKSIZE as u64 + 7, &mut buf), Err(Errno::Enomem));
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
        Fault::InconsistentFooter, Fault::SkipWrite, Fault::Kmalloc, Fault::Kvmalloc,
        Fault::PageAlloc, Fault::PageGet, Fault::SlabAlloc, Fault::Vmalloc,
    ];
    // Two are reserved by the ABI for requests that can no longer fail, one
    // names a filesystem-operation lock this design has no equivalent of, and
    // two name timeouts on waits that never happen here.
    let unwired = [
        Fault::AllocBio, Fault::Discard, Fault::LockOp, Fault::AtomicTimeout,
        Fault::LockTimeout,
    ];
    assert_eq!(wired.len() + unwired.len(), crate::fault::FAULT_MAX as usize,
               "a site was added to the ABI and neither wired nor accounted for");
    for i in 0..crate::fault::FAULT_MAX {
        let f = Fault::from_index(i).unwrap();
        assert!(wired.contains(&f) || unwired.contains(&f), "site {} is in neither list", f.name());
    }
}
