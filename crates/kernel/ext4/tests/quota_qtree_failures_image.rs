extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Kqid, MemDqblk, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_PRJ_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const HELLO_INO: u32 = 12;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;
const EMPTY_QTREE_INSERT_QBLK_WRITES: u32 = 9;

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn patch_u32(disk: &Arc<dyn BlockDevice>, offset: usize, value: u32) {
    let start_block = (offset / SECTOR as usize) as u64;
    let in_block = offset % SECTOR as usize;
    let mut buffer = vec![0u8; SECTOR as usize];
    let mut req = BlockRequest { op: BlockOp::Read, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("read fixture sector");
    buffer = req.buffer;
    buffer[in_block..in_block + 4].copy_from_slice(&value.to_le_bytes());
    let mut req = BlockRequest { op: BlockOp::Write, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("write fixture sector");
}

fn empty_project_quota_file() -> Vec<u8> {
    let mut q = vec![0u8; 2048];
    q[0..4].copy_from_slice(&PRJ_MAGIC.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

fn seeded_quota_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    drop(m);
    patch_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    disk
}

fn mount_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

#[test]
fn qtree_insert_qinfo_failure_removes_new_quota_record() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(42);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 1024, ..MemDqblk::new() }).expect("dirty new quota record");
    m.state().mount.fail_next_quota_info_write_for_tests();
    assert_eq!(vfs::quota_sync(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    drop(sb); drop(m);

    let (_m2, sb2) = mount_result(disk).expect("remount after failed insert");
    assert_eq!(vfs::quota_getnextquota(&sb2, Kqid::project(1)), Err(vfs::VfsError::Enoent));
    assert_eq!(vfs::quota_getquota(&sb2, qid).expect("absent quota shell").dqb_curspace, 0);
}

#[test]
fn qtree_insert_record_failure_removes_new_quota_record() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(43);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 2048, ..MemDqblk::new() }).expect("dirty new quota record");
    m.state().mount.fail_next_quota_record_write_for_tests();
    assert_eq!(vfs::quota_sync(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    drop(sb); drop(m);

    let (_m2, sb2) = mount_result(disk.clone()).expect("remount after failed record write");
    assert_eq!(vfs::quota_getnextquota(&sb2, Kqid::project(1)), Err(vfs::VfsError::Enoent));
    assert_eq!(vfs::quota_getquota(&sb2, qid).expect("absent quota shell").dqb_curspace, 0);
    drop(sb2); drop(_m2);

    let (_m3, sb3) = mount_result(disk).expect("remount for successful retry");
    vfs::quota_setquota(&sb3, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).expect("retry quota set");
    vfs::quota_sync(&sb3, vfs::QuotaType::Project).expect("retry quota sync");
    assert_eq!(vfs::quota_getnextquota(&sb3, Kqid::project(1)).expect("retry record reachable").0, qid);
    assert_eq!(vfs::quota_getquota(&sb3, qid).expect("retry record").dqb_curspace, 4096);
}

#[test]
fn qtree_insert_record_failure_cleanup_qblk_failure_is_retryable() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(44);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 8192, ..MemDqblk::new() }).expect("dirty new quota record");
    m.state().mount.fail_next_quota_record_write_for_tests();
    m.state().mount.fail_quota_qblk_write_after_for_tests(EMPTY_QTREE_INSERT_QBLK_WRITES);
    assert_eq!(vfs::quota_sync(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    drop(sb); drop(m);

    let (_m2, sb2) = mount_result(disk.clone()).expect("remount after failed cleanup");
    assert_eq!(vfs::quota_getnextquota(&sb2, Kqid::project(1)), Err(vfs::VfsError::Enoent));
    assert_eq!(vfs::quota_getquota(&sb2, qid).expect("empty leaf quota shell").dqb_curspace, 0);
    drop(sb2); drop(_m2);

    let (_m3, sb3) = mount_result(disk).expect("remount for retry after failed cleanup");
    vfs::quota_setquota(&sb3, qid, MemDqblk { dqb_curspace: 16 * 1024, ..MemDqblk::new() }).expect("retry quota set");
    vfs::quota_sync(&sb3, vfs::QuotaType::Project).expect("retry quota sync");
    assert_eq!(vfs::quota_getnextquota(&sb3, Kqid::project(1)).expect("retry record reachable").0, qid);
    assert_eq!(vfs::quota_getquota(&sb3, qid).expect("retry record").dqb_curspace, 16 * 1024);
}

#[test]
fn qtree_release_qinfo_failure_keeps_quota_off_retryable() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(45);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).expect("seed quota record");
    vfs::quota_sync(&sb, vfs::QuotaType::Project).expect("sync seeded record");
    vfs::quota_setquota(&sb, qid, MemDqblk::new()).expect("make quota record fake");
    m.state().mount.fail_quota_info_write_after_for_tests(1);
    assert_eq!(vfs::quota_off(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    assert!(sb.s_dquot.is_closing(vfs::QuotaType::Project), "failed release keeps quota-off retryable");

    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("retry quota_off after release qinfo failure");
    drop(sb); drop(m);

    let (_m2, sb2) = mount_result(disk).expect("remount after release retry");
    assert_eq!(vfs::quota_getnextquota(&sb2, Kqid::project(1)), Err(vfs::VfsError::Enoent));
    assert_eq!(vfs::quota_getquota(&sb2, qid).expect("released quota shell").dqb_curspace, 0);
}

#[test]
fn qtree_release_qinfo_failure_rollback_record_failure_keeps_quota_off_retryable() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(46);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).expect("seed quota record");
    vfs::quota_sync(&sb, vfs::QuotaType::Project).expect("sync seeded record");
    vfs::quota_setquota(&sb, qid, MemDqblk::new()).expect("make quota record fake");
    m.state().mount.fail_quota_info_write_after_for_tests(1);
    m.state().mount.fail_next_quota_record_write_for_tests();
    assert_eq!(vfs::quota_off(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    assert!(sb.s_dquot.is_closing(vfs::QuotaType::Project), "failed release rollback keeps quota-off retryable");

    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("retry quota_off after failed release rollback");
    drop(sb); drop(m);

    let (_m2, sb2) = mount_result(disk).expect("remount after release rollback retry");
    assert_eq!(vfs::quota_getnextquota(&sb2, Kqid::project(1)), Err(vfs::VfsError::Enoent));
    assert_eq!(vfs::quota_getquota(&sb2, qid).expect("released quota shell").dqb_curspace, 0);
}
