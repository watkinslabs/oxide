extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::inode::FS_PROJINHERIT_FL;
use vfs::{CreateCtx, FileAttr, FileType, Kqid, MemDqblk, SuperBlock, VfsError};

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

fn set_project_dir(m: &Arc<ext4::rootfs::Ext4Mount>, path: &[u8], projid: u32) {
    m.state().mkdir_at(path, 0o755).expect("mkdir project dir");
    let dir = m.state().lookup_inode_any(path).expect("lookup project dir");
    let flags = dir.fileattr_get().expect("project dir attrs").flags;
    dir.fileattr_set(&FileAttr { flags: flags | FS_PROJINHERIT_FL, fsx_projid: projid, ..Default::default() })
        .expect("set project inherit");
}

#[test]
fn whiteout_rename_charges_project_inode_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);

    m.state().create_at(b"/wo-src.txt", 0o644).expect("create source");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after source").dqb_curinodes, 1);

    m.state().whiteout_at(b"/wo-src.txt", b"/wo-dst.txt").expect("whiteout rename");

    let src = m.state().lookup_inode_any(b"/wo-src.txt").expect("whiteout source");
    let dst = m.state().lookup_inode_any(b"/wo-dst.txt").expect("whiteout dest");
    assert_eq!(src.file_type(), FileType::CharDev, "source becomes whiteout");
    assert_eq!(src.rdev(), 0, "whiteout rdev is 0:0");
    assert_eq!(dst.file_type(), FileType::Regular, "dest gets moved source inode");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after whiteout").dqb_curinodes, 2);
}

#[test]
fn whiteout_rejects_cross_project_inherit_destination_without_quota_change() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid_a = Kqid::project(10);
    let qid_b = Kqid::project(20);
    set_project_dir(&m, b"/wo-proj-a", 10);
    set_project_dir(&m, b"/wo-proj-b", 20);
    let src = m.state().create_at(b"/wo-proj-a/src", 0o644).expect("create source");
    let src_ino = src.ino() as u32;
    let before_a = vfs::quota_getquota(&sb, qid_a).expect("project a before");
    let before_b = vfs::quota_getquota(&sb, qid_b).expect("project b before");
    drop(src);

    assert_eq!(
        m.state().whiteout_at(b"/wo-proj-a/src", b"/wo-proj-b/dst"),
        Err(vfs::VfsError::Exdev),
    );

    assert_eq!(m.state().lookup_path(b"/wo-proj-a/src"), Some(src_ino));
    assert!(m.state().lookup_inode_any(b"/wo-proj-b/dst").is_none(), "failed whiteout creates no dest");
    assert_eq!(m.state().lookup_inode_any(b"/wo-proj-a/src").expect("source remains").file_type(), FileType::Regular);
    let after_a = vfs::quota_getquota(&sb, qid_a).expect("project a after");
    let after_b = vfs::quota_getquota(&sb, qid_b).expect("project b after");
    assert_eq!(after_a.dqb_curinodes, before_a.dqb_curinodes);
    assert_eq!(after_a.dqb_curspace, before_a.dqb_curspace);
    assert_eq!(after_b.dqb_curinodes, before_b.dqb_curinodes);
    assert_eq!(after_b.dqb_curspace, before_b.dqb_curspace);
}

#[test]
fn whiteout_rename_edquot_leaves_names_and_quota_unchanged() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);

    m.state().create_at(b"/wo-edquot-src.txt", 0o644).expect("create source");
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bhardlimit: 100, dqb_ihardlimit: 1, dqb_curinodes: 1, ..MemDqblk::new() })
        .expect("set inode hardlimit at current usage");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    assert_eq!(
        m.state().whiteout_at(b"/wo-edquot-src.txt", b"/wo-edquot-dst.txt"),
        Err(vfs::VfsError::Edquot),
    );

    let src = m.state().lookup_inode_any(b"/wo-edquot-src.txt").expect("source remains");
    assert_eq!(src.file_type(), FileType::Regular, "failed whiteout leaves source regular");
    assert!(m.state().lookup_inode_any(b"/wo-edquot-dst.txt").is_none(), "failed whiteout creates no dest");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after EDQUOT").dqb_curinodes, 1);
}

#[test]
fn vfs_whiteout_rename_edquot_leaves_names_and_quota_unchanged() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");

    let src = root.create_child("iop-wo-edquot-src.txt", 0o644, &CreateCtx::root()).expect("create source");
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bhardlimit: 100, dqb_ihardlimit: 1, dqb_curinodes: 1, ..MemDqblk::new() })
        .expect("set inode hardlimit at current usage");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    assert_eq!(
        root.rename_child("iop-wo-edquot-src.txt", &root, "iop-wo-edquot-dst.txt", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root()),
        Err(vfs::VfsError::Edquot),
    );

    let src_after = root.lookup("iop-wo-edquot-src.txt").expect("source remains");
    assert_eq!(src_after.ino(), src.ino());
    assert_eq!(src_after.file_type(), FileType::Regular, "failed whiteout leaves source regular");
    assert!(m.state().lookup_inode_any(b"/iop-wo-edquot-dst.txt").is_none(), "failed whiteout creates no dest");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after EDQUOT").dqb_curinodes, 1);
}

#[test]
fn whiteout_overwrite_quota_release_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let src = m.state().create_at(b"/wo-quota-src.txt", 0o644).expect("create source");
    let dst = m.state().create_at(b"/wo-quota-dst.txt", 0o644).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let before_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(src);
    drop(dst);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = m.state().whiteout_at(b"/wo-quota-src.txt", b"/wo-quota-dst.txt").expect_err("quota release failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/wo-quota-src.txt"), Some(src_ino));
    assert_eq!(m.state().lookup_path(b"/wo-quota-dst.txt"), Some(dst_ino));
    assert_eq!(m.state().lookup_inode_any(b"/wo-quota-src.txt").expect("source remains").file_type(), FileType::Regular);
    assert_eq!(m.state().lookup_inode_any(b"/wo-quota-dst.txt").expect("dest remains").file_type(), FileType::Regular);
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
fn vfs_whiteout_overwrite_quota_release_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("iop-wo-quota-src.txt", 0o644, &CreateCtx::root()).expect("create source");
    let dst = root.create_child("iop-wo-quota-dst.txt", 0o644, &CreateCtx::root()).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let before_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = root.rename_child("iop-wo-quota-src.txt", &root, "iop-wo-quota-dst.txt", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root())
        .expect_err("quota release failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-wo-quota-src.txt"), Some(src_ino));
    assert_eq!(m.state().lookup_path(b"/iop-wo-quota-dst.txt"), Some(dst_ino));
    assert_eq!(root.lookup("iop-wo-quota-src.txt").expect("source remains").ino(), src.ino());
    assert_eq!(root.lookup("iop-wo-quota-dst.txt").expect("dest remains").ino(), dst.ino());
    assert_eq!(root.lookup("iop-wo-quota-src.txt").expect("source remains").file_type(), FileType::Regular);
    assert_eq!(root.lookup("iop-wo-quota-dst.txt").expect("dest remains").file_type(), FileType::Regular);
    assert_eq!(dst.nlink(), 1, "failed overwrite keeps cached dest linked");
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
fn whiteout_inode_write_failure_cleanup_quota_dirty_failure_preserves_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let src = m.state().create_at(b"/wo-cleanup-src.txt", 0o644).expect("create source");
    let src_ino = src.ino() as u32;
    let before_src_raw = m.state().mount.read_inode(src_ino).expect("raw source before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(src);

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().whiteout_at(b"/wo-cleanup-src.txt", b"/wo-cleanup-dst.txt")
        .expect_err("injected whiteout inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/wo-cleanup-src.txt"), Some(src_ino));
    assert!(m.state().lookup_inode_any(b"/wo-cleanup-dst.txt").is_none(), "failed whiteout creates no dest");
    assert_eq!(m.state().lookup_inode_any(b"/wo-cleanup-src.txt").expect("source remains").file_type(), FileType::Regular);
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_src_raw = m.state().mount.read_inode(src_ino).expect("raw source after");
    assert_eq!(after_src_raw.links_count, before_src_raw.links_count);
    assert_eq!(after_src_raw.size, before_src_raw.size);
    assert_eq!(after_src_raw.i_blocks, before_src_raw.i_blocks);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_whiteout_inode_write_failure_cleanup_quota_dirty_failure_preserves_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("iop-wo-cleanup-src.txt", 0o644, &CreateCtx::root()).expect("create source");
    let src_ino = src.ino() as u32;
    let before_src_raw = m.state().mount.read_inode(src_ino).expect("raw source before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.rename_child("iop-wo-cleanup-src.txt", &root, "iop-wo-cleanup-dst.txt", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root())
        .expect_err("injected whiteout inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-wo-cleanup-src.txt"), Some(src_ino));
    assert!(m.state().lookup_inode_any(b"/iop-wo-cleanup-dst.txt").is_none(), "failed whiteout creates no dest");
    assert_eq!(root.lookup("iop-wo-cleanup-src.txt").expect("source remains").ino(), src.ino());
    assert_eq!(root.lookup("iop-wo-cleanup-src.txt").expect("source remains").file_type(), FileType::Regular);
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_src_raw = m.state().mount.read_inode(src_ino).expect("raw source after");
    assert_eq!(after_src_raw.links_count, before_src_raw.links_count);
    assert_eq!(after_src_raw.size, before_src_raw.size);
    assert_eq!(after_src_raw.i_blocks, before_src_raw.i_blocks);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}
