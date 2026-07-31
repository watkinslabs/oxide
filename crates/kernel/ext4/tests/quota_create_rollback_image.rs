extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::inode::FS_PROJINHERIT_FL;
use vfs::{CreateCtx, FileAttr, Kqid, SuperBlock, VfsError};

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
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A7, String::from("ext4"))?;
    Ok((m, sb))
}

fn set_project_dir(m: &Arc<ext4::rootfs::Ext4Mount>, path: &[u8], projid: u32) {
    m.state().mkdir_at(path, 0o755).expect("mkdir project dir");
    let dir = m.state().lookup_inode_any(path).expect("lookup project dir");
    let flags = dir.fileattr_get().expect("project dir attrs").flags;
    dir.fileattr_set(&FileAttr { flags: flags | FS_PROJINHERIT_FL, fsx_projid: projid, ..Default::default() })
        .expect("set project inherit");
}

fn quota(sb: &SuperBlock, qid: Kqid) -> vfs::MemDqblk {
    vfs::quota_getquota(sb, qid).expect("quota record")
}

fn assert_direct_rollback(m: &Arc<ext4::rootfs::Ext4Mount>, sb: &SuperBlock, qid: Kqid, path: &[u8], before: vfs::MemDqblk, free_inodes: u32) {
    assert!(m.state().lookup_inode_any(path).is_none(), "failed create must not leave namespace entry");
    assert_eq!(m.state().mount.state_free_inodes(), free_inodes, "failed create must return the inode");
    let after = quota(sb, qid);
    assert_eq!(after.dqb_curinodes, before.dqb_curinodes, "failed create must release inode quota");
    assert_eq!(after.dqb_curspace, before.dqb_curspace, "failed create must not change block quota");
}

fn assert_iop_rollback(dir: &vfs::InodeRef, name: &str, m: &Arc<ext4::rootfs::Ext4Mount>, sb: &SuperBlock, qid: Kqid, before: vfs::MemDqblk, free_inodes: u32) {
    assert!(dir.lookup(name).is_err(), "failed i_op create must not leave namespace entry");
    assert_eq!(m.state().mount.state_free_inodes(), free_inodes, "failed i_op create must return the inode");
    let after = quota(sb, qid);
    assert_eq!(after.dqb_curinodes, before.dqb_curinodes, "failed i_op create must release inode quota");
    assert_eq!(after.dqb_curspace, before.dqb_curspace, "failed i_op create must not change block quota");
}

#[test]
fn create_family_inode_write_failure_releases_project_quota_charge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/proj", 123);
    let base = quota(&sb, qid);
    assert_eq!(base.dqb_curinodes, 1);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert!(m.state().create_at(b"/proj/file", 0o644).is_none(), "create must fail at inode write");
    assert_direct_rollback(&m, &sb, qid, b"/proj/file", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(m.state().mkdir_at(b"/proj/dir", 0o755), Err(VfsError::Eio));
    assert_direct_rollback(&m, &sb, qid, b"/proj/dir", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(m.state().symlink_at(b"file", b"/proj/link"), Err(VfsError::Eio));
    assert_direct_rollback(&m, &sb, qid, b"/proj/link", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(m.state().mknod_at(b"/proj/fifo", (vfs::S_IFIFO as u16) | 0o600, 0), Err(VfsError::Eio));
    assert_direct_rollback(&m, &sb, qid, b"/proj/fifo", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert!(m.state().create_anonymous_at(b"/proj", 0o600).is_none(), "tmpfile must fail at inode write");
    assert_eq!(m.state().mount.state_free_inodes(), free, "failed tmpfile must return the inode");
    assert_eq!(quota(&sb, qid).dqb_curinodes, base.dqb_curinodes, "failed tmpfile must release inode quota");
}

#[test]
fn vfs_create_family_inode_write_failure_releases_project_quota_charge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/iop-proj", 123);
    let dir = m.state().lookup_inode_any(b"/iop-proj").expect("lookup project dir");
    let base = quota(&sb, qid);
    assert_eq!(base.dqb_curinodes, 1);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    match dir.create_child("file", 0o644, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Eio),
        Ok(_) => panic!("create unexpectedly succeeded"),
    }
    assert_iop_rollback(&dir, "file", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    match dir.mkdir("dir", 0o755, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Eio),
        Ok(_) => panic!("mkdir unexpectedly succeeded"),
    }
    assert_iop_rollback(&dir, "dir", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(dir.symlink_child("link", b"file", &CreateCtx::root()), Err(VfsError::Eio));
    assert_iop_rollback(&dir, "link", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(dir.mknod_child("fifo", (vfs::S_IFIFO as u16) | 0o600, 0, &CreateCtx::root()), Err(VfsError::Eio));
    assert_iop_rollback(&dir, "fifo", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_next_inode_write_for_tests();
    match dir.tmpfile(0o600, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Eio),
        Ok(_) => panic!("tmpfile unexpectedly succeeded"),
    }
    assert_eq!(m.state().mount.state_free_inodes(), free, "failed i_op tmpfile must return the inode");
    let after = quota(&sb, qid);
    assert_eq!(after.dqb_curinodes, base.dqb_curinodes, "failed i_op tmpfile must release inode quota");
    assert_eq!(after.dqb_curspace, base.dqb_curspace, "failed i_op tmpfile must not change block quota");
}

#[test]
fn create_family_inode_write_and_cleanup_dirty_failure_releases_project_quota_charge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/dirty-proj", 123);
    let base = quota(&sb, qid);
    assert_eq!(base.dqb_curinodes, 1);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert!(m.state().create_at(b"/dirty-proj/file", 0o644).is_none(), "create must fail at inode write");
    assert_direct_rollback(&m, &sb, qid, b"/dirty-proj/file", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(m.state().mkdir_at(b"/dirty-proj/dir", 0o755), Err(VfsError::Eio));
    assert_direct_rollback(&m, &sb, qid, b"/dirty-proj/dir", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(m.state().symlink_at(b"file", b"/dirty-proj/link"), Err(VfsError::Eio));
    assert_direct_rollback(&m, &sb, qid, b"/dirty-proj/link", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(m.state().mknod_at(b"/dirty-proj/fifo", (vfs::S_IFIFO as u16) | 0o600, 0), Err(VfsError::Eio));
    assert_direct_rollback(&m, &sb, qid, b"/dirty-proj/fifo", base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert!(m.state().create_anonymous_at(b"/dirty-proj", 0o600).is_none(), "tmpfile must fail at inode write");
    assert_eq!(m.state().mount.state_free_inodes(), free, "failed tmpfile must return the inode");
    let after = quota(&sb, qid);
    assert_eq!(after.dqb_curinodes, base.dqb_curinodes, "failed tmpfile must release inode quota");
    assert_eq!(after.dqb_curspace, base.dqb_curspace, "failed tmpfile must not change block quota");
}

#[test]
fn vfs_create_family_inode_write_and_cleanup_dirty_failure_releases_project_quota_charge() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/iop-dirty-proj", 123);
    let dir = m.state().lookup_inode_any(b"/iop-dirty-proj").expect("lookup project dir");
    let base = quota(&sb, qid);
    assert_eq!(base.dqb_curinodes, 1);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    match dir.create_child("file", 0o644, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Eio),
        Ok(_) => panic!("create unexpectedly succeeded"),
    }
    assert_iop_rollback(&dir, "file", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    match dir.mkdir("dir", 0o755, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Eio),
        Ok(_) => panic!("mkdir unexpectedly succeeded"),
    }
    assert_iop_rollback(&dir, "dir", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(dir.symlink_child("link", b"file", &CreateCtx::root()), Err(VfsError::Eio));
    assert_iop_rollback(&dir, "link", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(dir.mknod_child("fifo", (vfs::S_IFIFO as u16) | 0o600, 0, &CreateCtx::root()), Err(VfsError::Eio));
    assert_iop_rollback(&dir, "fifo", &m, &sb, qid, base, free);

    let free = m.state().mount.state_free_inodes();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(1);
    m.state().mount.fail_next_inode_write_for_tests();
    match dir.tmpfile(0o600, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Eio),
        Ok(_) => panic!("tmpfile unexpectedly succeeded"),
    }
    assert_eq!(m.state().mount.state_free_inodes(), free, "failed i_op tmpfile must return the inode");
    let after = quota(&sb, qid);
    assert_eq!(after.dqb_curinodes, base.dqb_curinodes, "failed i_op tmpfile must release inode quota");
    assert_eq!(after.dqb_curspace, base.dqb_curspace, "failed i_op tmpfile must not change block quota");
}
