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
fn same_path_rename_noops_without_releasing_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let file = m.state().create_at(b"/same-rename.txt", 0o644).expect("create file");
    let ino = file.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x51; (bs * 2) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before direct rename");
    let before_map = m.state().mount.extent_map(ino).expect("map before direct rename");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before direct rename");
    drop(file);

    m.state().rename_at(b"/same-rename.txt", b"/same-rename.txt").expect("same-path direct rename");

    assert_eq!(m.state().lookup_path(b"/same-rename.txt"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after direct rename");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(m.state().mount.extent_map(ino).expect("map after direct rename"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after direct rename");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);

    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota for vfs rename");
    let root = sb.s_root_inode().expect("root inode");
    let file = root.create_child("iop-same-rename.txt", 0o644, &CreateCtx::root()).expect("create vfs file");
    let ino = file.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x52; (bs * 2) as usize]).expect("seed vfs file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before vfs rename");
    let before_map = m.state().mount.extent_map(ino).expect("map before vfs rename");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before vfs rename");

    root.rename_child("iop-same-rename.txt", &root, "iop-same-rename.txt", 0, &CreateCtx::root())
        .expect("same-path vfs rename");

    assert_eq!(m.state().lookup_path(b"/iop-same-rename.txt"), Some(ino));
    assert_eq!(root.lookup("iop-same-rename.txt").expect("file remains").ino(), file.ino());
    assert_eq!(file.nlink(), before_raw.links_count.into());
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after vfs rename");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(m.state().mount.extent_map(ino).expect("map after vfs rename"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after vfs rename");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn final_unlink_inode_write_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/unlink-rollback-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0xA9; (bs * 2) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(before_q.dqb_curinodes, 1);
    assert_eq!(before_q.dqb_curspace, before_raw.i_blocks as u64 * 512);
    drop(inode);

    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().unlink_at(b"/unlink-rollback-quota.txt").expect_err("injected unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/unlink-rollback-quota.txt"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// A failed quota release CANNOT roll an unlink back, and this test used to
/// assert that it did (EIO returned, dirent preserved). That expectation was
/// never Linux: `__ext4_unlink` (`fs/ext4/namei.c`) calls no dquot function at
/// all — it deletes the entry, `drop_nlink`s and `ext4_orphan_add`s. The
/// release is `dquot_free_inode` inside `ext4_free_inode`
/// (`fs/ext4/ialloc.c:275`), reached from `ext4_evict_inode`
/// (`fs/ext4/inode.c:319`), and `ext4_free_inode` returns `void` — by then the
/// name is long gone and there is nothing to undo.
///
/// The real contract: the unlink succeeds, and because nothing holds this
/// inode the eviction runs inline, where `RootfsState::free_orphan_inode`
/// releases through `release_existing_inode_retry` — which absorbs exactly one
/// failed `mark_dirty`. So the accounting still lands and the blocks and the
/// inode slot both come back.
#[test]
fn final_unlink_quota_release_failure_is_retried_at_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let base_free_inodes = m.state().mount.state_free_inodes();
    let base_q = vfs::quota_getquota(&sb, qid).expect("quota before create");

    let inode = m.state().create_at(b"/unlink-quota-release-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let free_blocks_before_data = m.state().mount.state_free_blocks();
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xC3; (bs * 2) as usize]).expect("seed file data");
    let charged = m.state().mount.read_inode(ino).expect("raw before").i_blocks as u64 * 512;
    assert_ne!(charged, 0, "the victim must own blocks for the space release to mean anything");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(before_q.dqb_curinodes, base_q.dqb_curinodes + 1);
    assert_eq!(before_q.dqb_curspace, base_q.dqb_curspace + charged);
    drop(inode);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    m.state().unlink_at(b"/unlink-quota-release-fail.txt")
        .expect("unlink succeeds — no dquot call can fail it");

    assert_eq!(m.state().lookup_path(b"/unlink-quota-release-fail.txt"), None, "the name is gone");
    assert_eq!(m.state().mount.state_free_blocks(), free_blocks_before_data, "eviction gave the blocks back");
    assert_eq!(m.state().mount.state_free_inodes(), base_free_inodes, "eviction gave the inode slot back");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, base_q.dqb_curinodes, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, base_q.dqb_curspace);
}

#[test]
fn vfs_final_unlink_inode_write_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let file = root.create_child("iop-unlink-rollback-quota.txt", 0o644, &CreateCtx::root()).expect("create file");
    let ino = file.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0xB1; (bs * 2) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.unlink_child("iop-unlink-rollback-quota.txt").expect_err("injected unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-unlink-rollback-quota.txt"), Some(ino));
    assert_eq!(root.lookup("iop-unlink-rollback-quota.txt").expect("cached source remains").ino(), file.ino());
    assert_eq!(file.nlink(), 1, "failed unlink keeps cached link count");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// Same correction as [`final_unlink_quota_release_failure_is_retried_at_eviction`]
/// through `i_op->unlink`, and one step further: the test holds `file`, so the
/// eviction is DEFERRED. `__ext4_unlink` (`fs/ext4/namei.c`) removes the name
/// and orphans the inode without touching quota; the armed `mark_dirty`
/// failure therefore cannot reach the unlink at all, and only fires later,
/// inside `ext4_evict_inode` → `ext4_free_inode` → `dquot_free_inode`
/// (`fs/ext4/ialloc.c:275`), where `release_existing_inode_retry` absorbs it.
#[test]
fn vfs_final_unlink_quota_release_failure_is_retried_at_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let base_free_inodes = m.state().mount.state_free_inodes();
    let base_q = vfs::quota_getquota(&sb, qid).expect("quota before create");

    let file = root.create_child("iop-unlink-quota-release-fail.txt", 0o644, &CreateCtx::root()).expect("create file");
    let ino = file.ino() as u32;
    let free_blocks_before_data = m.state().mount.state_free_blocks();
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xD4; (bs * 2) as usize]).expect("seed file data");
    let charged = m.state().mount.read_inode(ino).expect("raw before").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(before_q.dqb_curinodes, base_q.dqb_curinodes + 1);
    assert_eq!(before_q.dqb_curspace, base_q.dqb_curspace + charged);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    root.unlink_child("iop-unlink-quota-release-fail.txt")
        .expect("unlink succeeds — no dquot call can fail it");

    assert_eq!(m.state().lookup_path(b"/iop-unlink-quota-release-fail.txt"), None, "the name is gone");
    assert!(root.lookup("iop-unlink-quota-release-fail.txt").is_err(), "the dcache entry is gone too");
    assert_eq!(file.nlink(), 0, "the final unlink zeroed the cached link count");
    // Held-across-unlink invariant: nothing is freed while `file` lives.
    assert_eq!(m.state().mount.state_free_inodes(), base_free_inodes - 1, "the inode slot is still in use");
    let held_q = vfs::quota_getquota(&sb, qid).expect("quota while held");
    assert_eq!(held_q.dqb_curinodes, before_q.dqb_curinodes, "unlink-while-held keeps the inode charged");
    assert_eq!(held_q.dqb_curspace, before_q.dqb_curspace, "unlink-while-held keeps the space charged");

    vfs::file::iput(file);

    assert_eq!(m.state().mount.state_free_blocks(), free_blocks_before_data, "eviction gave the blocks back");
    assert_eq!(m.state().mount.state_free_inodes(), base_free_inodes, "eviction gave the inode slot back");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after eviction");
    assert_eq!(after_q.dqb_curinodes, base_q.dqb_curinodes, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, base_q.dqb_curspace);
}

#[test]
fn final_rmdir_quota_release_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    m.state().mkdir_at(b"/rmdir-quota-release-fail", 0o755).expect("mkdir");
    let dir = m.state().lookup_inode_any(b"/rmdir-quota-release-fail").expect("lookup dir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(dir);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = m.state().rmdir_at(b"/rmdir-quota-release-fail").expect_err("quota release failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/rmdir-quota-release-fail"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after_root = m.state().mount.read_inode(2).expect("root after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_root.links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_final_rmdir_inode_write_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let dir = root.mkdir("iop-rmdir-rollback-quota", 0o755, &CreateCtx::root()).expect("mkdir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = root.rmdir("iop-rmdir-rollback-quota").expect_err("injected rmdir inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-rmdir-rollback-quota"), Some(ino));
    assert_eq!(root.lookup("iop-rmdir-rollback-quota").expect("dir remains").ino(), dir.ino());
    assert_eq!(dir.nlink(), before_raw.links_count.into(), "failed rmdir keeps cached link count");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after_root = m.state().mount.read_inode(2).expect("root after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_root.links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn vfs_final_rmdir_quota_release_failure_preserves_namespace_and_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let dir = root.mkdir("iop-rmdir-quota-release-fail", 0o755, &CreateCtx::root()).expect("mkdir");
    let ino = dir.ino() as u32;
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = root.rmdir("iop-rmdir-quota-release-fail").expect_err("quota release failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/iop-rmdir-quota-release-fail"), Some(ino));
    assert_eq!(root.lookup("iop-rmdir-quota-release-fail").expect("dir remains").ino(), dir.ino());
    assert_eq!(dir.nlink(), before_raw.links_count.into(), "failed rmdir keeps cached link count");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after_root = m.state().mount.read_inode(2).expect("root after");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_root.links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// A REGULAR-file rename victim now follows the unlink contract, so this test's
/// old expectation (EIO, both names preserved) was wrong for the same reason:
/// `ext4_rename` (`fs/ext4/namei.c`) only `ext4_dec_count(new.inode)` and
/// `ext4_orphan_add(handle, new.inode)`s the victim — no dquot call — leaving
/// `dquot_free_inode` in `ext4_free_inode` (`fs/ext4/ialloc.c:275`) to release
/// it at eviction, where nothing can un-rename anything.
///
/// Here neither side is held, so the victim's eviction runs inline inside the
/// rename and `release_existing_inode_retry` absorbs the injected failure.
#[test]
fn rename_overwrite_quota_release_failure_is_retried_at_victim_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let src = m.state().create_at(b"/rename-quota-src.txt", 0o644).expect("create source");
    let dst = m.state().create_at(b"/rename-quota-dst.txt", 0o644).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(dst_ino, 0, &vec![0xE5; (bs * 2) as usize]).expect("seed victim data");
    let victim_space = m.state().mount.read_inode(dst_ino).expect("raw dest before").i_blocks as u64 * 512;
    assert_ne!(victim_space, 0);
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    drop(src);
    drop(dst);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    m.state().rename_at(b"/rename-quota-src.txt", b"/rename-quota-dst.txt")
        .expect("rename succeeds — a regular victim's release is not on the rename path");

    assert_eq!(m.state().lookup_path(b"/rename-quota-src.txt"), None, "the source name is gone");
    assert_eq!(m.state().lookup_path(b"/rename-quota-dst.txt"), Some(src_ino), "the destination names the source");
    assert!(m.state().mount.read_inode(dst_ino).map(|i| i.links_count).unwrap_or(0) == 0,
        "the replaced victim lost its last link");
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks + (victim_space / bs),
        "the victim's blocks came back at eviction");
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes + 1,
        "the victim's inode slot came back at eviction");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes - 1, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace - victim_space);
}

/// The path that genuinely still pre-releases and rolls back: a DIRECTORY
/// victim. `Mount::rmdir` frees a directory outright (a directory has no
/// open-fd data to preserve), so its charge is released up front — and a
/// failure there aborts the rename with the namespace and the quota intact,
/// exactly like `Ext4StatInodeOps::rmdir`. Contrast with the regular-file
/// victim above, which is merely orphaned.
#[test]
fn rename_overwrite_directory_victim_quota_release_failure_rolls_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    m.state().mkdir_at(b"/rename-quota-dir-src", 0o755).expect("mkdir source");
    m.state().mkdir_at(b"/rename-quota-dir-dst", 0o755).expect("mkdir dest");
    let src_ino = m.state().lookup_path(b"/rename-quota-dir-src").expect("source ino");
    let dst_ino = m.state().lookup_path(b"/rename-quota-dir-dst").expect("dest ino");
    let before_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest before");
    let before_root = m.state().mount.read_inode(2).expect("root before");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let err = m.state().rename_at(b"/rename-quota-dir-src", b"/rename-quota-dir-dst")
        .expect_err("up-front directory-victim release failure aborts the rename");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/rename-quota-dir-src"), Some(src_ino));
    assert_eq!(m.state().lookup_path(b"/rename-quota-dir-dst"), Some(dst_ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_dst_raw = m.state().mount.read_inode(dst_ino).expect("raw dest after");
    assert_eq!(after_dst_raw.links_count, before_dst_raw.links_count);
    assert_eq!(after_dst_raw.size, before_dst_raw.size);
    assert_eq!(after_dst_raw.i_blocks, before_dst_raw.i_blocks);
    assert_eq!(m.state().mount.read_inode(2).expect("root after").links_count, before_root.links_count);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

/// `i_op->rename` over a REGULAR-file victim that the test still HOLDS. Same
/// correction as the path-based case — `ext4_rename` (`fs/ext4/namei.c`) only
/// `ext4_dec_count`s + `ext4_orphan_add`s the victim, calling no dquot function
/// — plus the deferral: with `dst` alive the victim's blocks and charge outlive
/// the rename, and the armed `mark_dirty` failure only reaches
/// `dquot_free_inode` (`fs/ext4/ialloc.c:275`) at the eviction `iput` triggers,
/// where `release_existing_inode_retry` absorbs it.
#[test]
fn vfs_rename_overwrite_quota_release_failure_is_retried_at_victim_eviction() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("iop-rename-quota-src.txt", 0o644, &CreateCtx::root()).expect("create source");
    let dst = root.create_child("iop-rename-quota-dst.txt", 0o644, &CreateCtx::root()).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(dst_ino, 0, &vec![0xF6; (bs * 2) as usize]).expect("seed victim data");
    let victim_space = m.state().mount.read_inode(dst_ino).expect("raw dest before").i_blocks as u64 * 512;
    assert_ne!(victim_space, 0);
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    root.rename_child("iop-rename-quota-src.txt", &root, "iop-rename-quota-dst.txt", 0, &CreateCtx::root())
        .expect("rename succeeds — a regular victim's release is not on the rename path");

    assert_eq!(m.state().lookup_path(b"/iop-rename-quota-src.txt"), None, "the source name is gone");
    assert_eq!(m.state().lookup_path(b"/iop-rename-quota-dst.txt"), Some(src_ino), "the destination names the source");
    assert_eq!(dst.nlink(), 0, "the replaced victim lost its last link");
    // Held-across-rename invariant: the victim is orphaned, not freed.
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks, "the victim's blocks survive while held");
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes, "the victim's inode slot survives while held");
    let held_q = vfs::quota_getquota(&sb, qid).expect("quota while victim held");
    assert_eq!(held_q.dqb_curinodes, before_q.dqb_curinodes, "the victim stays charged while held");
    assert_eq!(held_q.dqb_curspace, before_q.dqb_curspace);

    vfs::file::iput(dst);

    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks + (victim_space / bs),
        "eviction gave the victim's blocks back");
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes + 1,
        "eviction gave the victim's inode slot back");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after eviction");
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes - 1, "the retried release still lands");
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace - victim_space);
    drop(src);
}
