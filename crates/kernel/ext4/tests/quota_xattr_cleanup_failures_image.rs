extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Kqid, SuperBlock};

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
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A9, String::from("ext4"))?;
    Ok((m, sb))
}

fn file_acl(ino_bytes: &[u8]) -> u64 {
    let lo = u32::from_le_bytes([ino_bytes[0x68], ino_bytes[0x69], ino_bytes[0x6A], ino_bytes[0x6B]]) as u64;
    let hi = u16::from_le_bytes([ino_bytes[0x76], ino_bytes[0x77]]) as u64;
    lo | (hi << 32)
}

#[test]
fn xattr_shrink_free_failure_preserves_quota_and_xattr_state() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/xattr-free-fail-state.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let value = vec![0xD4; 300];

    inode.setxattr("user.big", value.clone(), false, false).expect("create external xattr");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let (before_bytes, _) = m.state().mount.read_inode_bytes(ino).expect("inode bytes before");
    let before_acl = file_acl(&before_bytes);
    let before_free = m.state().mount.state_free_blocks();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert!(before_acl != 0);

    m.state().mount.fail_next_free_block_for_tests();
    let err = inode.removexattr("user.big").expect_err("injected block-free failure");

    assert_eq!(err, vfs::XattrError::Fs(vfs::VfsError::Eio));
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let (after_bytes, _) = m.state().mount.read_inode_bytes(ino).expect("inode bytes after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(file_acl(&after_bytes), before_acl);
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(inode.getxattr("user.big").expect("xattr cache after"), value);
}

#[test]
fn xattr_external_create_inode_failure_cleanup_free_failure_preserves_quota_and_cache() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/xattr-create-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let value = vec![0xC7; 300];
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let (before_bytes, _) = m.state().mount.read_inode_bytes(ino).expect("inode bytes before");
    let before_free = m.state().mount.state_free_blocks();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(file_acl(&before_bytes), 0);

    m.state().mount.fail_next_inode_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = inode.setxattr("user.big", value, false, false).expect_err("injected inode write and cleanup free failure");

    assert_eq!(err, vfs::XattrError::Fs(vfs::VfsError::Eio));
    assert_eq!(inode.getxattr("user.big"), Err(vfs::XattrError::NotFound));
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let (after_bytes, _) = m.state().mount.read_inode_bytes(ino).expect("inode bytes after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(file_acl(&after_bytes), 0);
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
}

#[test]
fn xattr_external_create_block_write_failure_cleanup_free_failure_preserves_quota_and_cache() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/xattr-create-block-write-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let value = vec![0xB6; 300];
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let (before_bytes, _) = m.state().mount.read_inode_bytes(ino).expect("inode bytes before");
    let before_free = m.state().mount.state_free_blocks();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(file_acl(&before_bytes), 0);

    m.state().mount.fail_metadata_write_after_for_tests(3);
    m.state().mount.fail_next_free_block_for_tests();
    let err = inode.setxattr("user.big", value, false, false).expect_err("injected xattr block write and cleanup free failure");

    assert_eq!(err, vfs::XattrError::Fs(vfs::VfsError::Eio));
    assert_eq!(inode.getxattr("user.big"), Err(vfs::XattrError::NotFound));
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let (after_bytes, _) = m.state().mount.read_inode_bytes(ino).expect("inode bytes after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(file_acl(&after_bytes), 0);
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after");
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
    assert_eq!(after_q.dqb_curinodes, before_q.dqb_curinodes);
}
