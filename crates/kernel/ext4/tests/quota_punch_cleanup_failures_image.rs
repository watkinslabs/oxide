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
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

#[test]
fn punch_rebuild_metadata_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-rebuild-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8, 10] {
        m.state().mount.write_at(ino, lb * bs, &[0xF5]).expect("seed external sparse extents");
    }
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    assert_eq!(ext4::parse_extent_header(&before_raw.i_block).expect("extent header").depth, 1);
    let before_free = m.state().mount.state_free_blocks();
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_extent_block_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.punch_hole_inode(ino, 4 * bs, bs).expect_err("replacement leaf write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn punch_multileaf_rebuild_second_leaf_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-multileaf-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    let leaf_max = ext4::csum::extent_block_max(&m.state().mount.sb, bs as usize) as u64;

    for n in 0..(leaf_max + 6) {
        m.state().mount.write_at(ino, n * 2 * bs, &[0xE7]).expect("seed sparse extents");
    }
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    assert_eq!(ext4::parse_extent_header(&before_raw.i_block).expect("extent header").depth, 1);
    let before_free = m.state().mount.state_free_blocks();
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_extent_block_write_after_for_tests(1);
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.punch_hole_inode(ino, leaf_max * bs, bs).expect_err("second replacement leaf write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn punch_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-free-fail-tree.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0xA7; (bs * 5) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.punch_hole_inode(ino, bs, bs * 2).expect_err("injected block-free failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn punch_partial_edges_free_failure_preserves_quota_tree_and_zeroed_edges() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-partial-edge-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    let half = (bs / 2) as usize;

    let mut seeded = Vec::new();
    for byte in [0x11u8, 0x22, 0x33, 0x44] {
        seeded.extend_from_slice(&vec![byte; bs as usize]);
    }
    m.state().mount.write_at(ino, 0, &seeded).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.punch_hole_inode(ino, bs / 2, bs * 2).expect_err("whole-block free fails");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    let after = m.state().read_full_file(ino).expect("file after failed punch");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
    assert_eq!(&after[..half], &seeded[..half]);
    assert!(after[half..bs as usize].iter().all(|&b| b == 0));
    assert_eq!(&after[bs as usize..(bs * 2) as usize], &seeded[bs as usize..(bs * 2) as usize]);
    assert!(after[(bs * 2) as usize..(bs * 2) as usize + half].iter().all(|&b| b == 0));
    assert_eq!(&after[(bs * 2) as usize + half..], &seeded[(bs * 2) as usize + half..]);
}
