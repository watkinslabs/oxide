extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{CreateCtx, Kqid, SuperBlock, VfsError};

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

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
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
fn rename_overwrite_inode_write_failure_retries_destination_quota_recharge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let src = m.state().create_at(b"/rename-recharge-src.txt", 0o644).expect("create source");
    let dst = m.state().create_at(b"/rename-recharge-dst.txt", 0o644).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let before_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(src);
    drop(dst);

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().rename_at(b"/rename-recharge-src.txt", b"/rename-recharge-dst.txt")
        .expect_err("injected rename inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/rename-recharge-src.txt"), Some(src_ino));
    assert_eq!(m.state().lookup_path(b"/rename-recharge-dst.txt"), Some(dst_ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest after");
    assert_eq!(after_dst_raw.links_count, before_dst_raw.links_count);
    assert_eq!(after_dst_raw.size, before_dst_raw.size);
    assert_eq!(after_dst_raw.i_blocks, before_dst_raw.i_blocks);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_rename_overwrite_inode_write_failure_retries_destination_quota_recharge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("iop-rename-recharge-src.txt", 0o644, &CreateCtx::root()).expect("create source");
    let dst = root.create_child("iop-rename-recharge-dst.txt", 0o644, &CreateCtx::root()).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let before_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.rename_child("iop-rename-recharge-src.txt", &root, "iop-rename-recharge-dst.txt", 0, &CreateCtx::root())
        .expect_err("injected rename inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-rename-recharge-src.txt"), Some(src_ino));
    assert_eq!(m.state().lookup_path(b"/iop-rename-recharge-dst.txt"), Some(dst_ino));
    assert_eq!(root.lookup("iop-rename-recharge-src.txt").expect("source remains").ino(), src.ino());
    assert_eq!(root.lookup("iop-rename-recharge-dst.txt").expect("dest remains").ino(), dst.ino());
    assert_eq!(dst.nlink(), before_dst_raw.links_count.into(), "failed overwrite keeps cached dest linked");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest after");
    assert_eq!(after_dst_raw.links_count, before_dst_raw.links_count);
    assert_eq!(after_dst_raw.size, before_dst_raw.size);
    assert_eq!(after_dst_raw.i_blocks, before_dst_raw.i_blocks);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn final_unlink_inode_write_failure_retries_quota_recharge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let file = m.state().create_at(b"/unlink-recharge.txt", 0o644).expect("create file");
    let ino = file.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(file);

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().unlink_at(b"/unlink-recharge.txt").expect_err("injected unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/unlink-recharge.txt"), Some(ino));
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn final_rmdir_inode_write_failure_retries_quota_recharge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    m.state().mkdir_at(b"/rmdir-recharge", 0o755).expect("mkdir");
    let ino = m.state().lookup_path(b"/rmdir-recharge").expect("lookup dir");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().rmdir_at(b"/rmdir-recharge").expect_err("injected rmdir inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/rmdir-recharge"), Some(ino));
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_final_unlink_inode_write_failure_retries_quota_recharge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let file = root.create_child("iop-unlink-recharge.txt", 0o644, &CreateCtx::root()).expect("create file");
    let ino = file.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.unlink_child("iop-unlink-recharge.txt").expect_err("injected vfs unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-unlink-recharge.txt"), Some(ino));
    assert_eq!(root.lookup("iop-unlink-recharge.txt").expect("source remains").ino(), file.ino());
    assert_eq!(file.nlink(), before_raw.links_count.into());
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_final_rmdir_inode_write_failure_retries_quota_recharge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let dir = root.mkdir("iop-rmdir-recharge", 0o755, &CreateCtx::root()).expect("mkdir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.rmdir("iop-rmdir-recharge").expect_err("injected vfs rmdir inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-rmdir-recharge"), Some(ino));
    assert_eq!(root.lookup("iop-rmdir-recharge").expect("dir remains").ino(), dir.ino());
    assert_eq!(dir.nlink(), before_raw.links_count.into());
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}
