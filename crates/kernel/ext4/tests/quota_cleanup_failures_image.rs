extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

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

fn read_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32) -> Vec<u8> {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Read, start_block: fs_lba * sectors as u64,
        len_blocks: sectors, buffer: vec![0u8; fs_bs as usize], ..Default::default() };
    disk.submit_sync(&mut req).expect("read fs block");
    req.buffer
}

fn write_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32, buffer: Vec<u8>) {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest { op: BlockOp::Write, start_block: fs_lba * sectors as u64, len_blocks: sectors, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("write fs block");
}

fn extent_entries(buf: &[u8]) -> u16 { u16::from_le_bytes([buf[2], buf[3]]) }
fn extent_depth(buf: &[u8]) -> u16 { u16::from_le_bytes([buf[6], buf[7]]) }

fn idx_lba(buf: &[u8], idx: usize) -> u64 {
    let off = 12 + idx * 12;
    let lo = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
    let hi = u16::from_le_bytes([buf[off + 8], buf[off + 9]]);
    ((hi as u64) << 32) | lo as u64
}

fn pin_external_maxes(disk: &Arc<dyn BlockDevice>, sb: &ext4::Superblock,
                      ino: u32, gen: u32, fs_lba: u64, fs_bs: u32) {
    let mut buf = read_fs_block(disk, fs_lba, fs_bs);
    let entries = extent_entries(&buf);
    let depth = extent_depth(&buf);
    buf[4..6].copy_from_slice(&entries.to_le_bytes());
    ext4::csum::stamp_extent_block_csum(sb, ino, gen, &mut buf);
    write_fs_block(disk, fs_lba, fs_bs, buf.clone());
    if depth > 0 {
        for i in 0..entries as usize { pin_external_maxes(disk, sb, ino, gen, idx_lba(&buf, i), fs_bs); }
    }
}

fn pin_tree_maxes(disk: &Arc<dyn BlockDevice>, sb: &ext4::Superblock,
                  ino: u32, gen: u32, i_block: &[u8], fs_bs: u32) {
    if extent_depth(i_block) == 0 { return; }
    for i in 0..extent_entries(i_block) as usize {
        pin_external_maxes(disk, sb, ino, gen, idx_lba(i_block, i), fs_bs);
    }
}

fn assert_inode_quota_unchanged_after_cleanup_abort(
    m: &ext4::rootfs::Ext4Mount, sb: &SuperBlock, qid: Kqid,
    ino: u32, before_free: u64, before_raw: &ext4::Inode, before_q: u64,
) {
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(vfs::quota_getquota(sb, qid).expect("quota after").dqb_curspace, before_q);
}

fn force_depth_two_tree(disk: &Arc<dyn BlockDevice>, m: &ext4::rootfs::Ext4Mount, ino: u32, bs: u64) {
    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xA1]).expect("seed external tree");
    }
    for lb in [10u64, 12, 14, 16] {
        let raw = m.state().mount.read_inode(ino).expect("raw before depth grow");
        pin_tree_maxes(disk, &m.state().mount.sb, ino, raw.generation, &raw.i_block, m.state().mount.sb.block_size);
        m.state().mount.write_at(ino, lb * bs, &[0xA2]).expect("grow depth two tree");
    }
    let raw = m.state().mount.read_inode(ino).expect("depth two raw");
    assert_eq!(ext4::parse_extent_header(&raw.i_block).expect("extent header").depth, 2);
}

#[test]
fn inline_write_cleanup_free_failure_preserves_original_error_and_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/inline-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_data_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.write_at(ino, 0, &vec![0xA6; bs as usize]).expect_err("data write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
}

#[test]
fn append_inline_cleanup_free_failure_preserves_original_error_and_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/append-inline-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as usize;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_data_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.append_block(ino, &vec![0xB1; bs]).expect_err("append data write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
}

#[test]
fn append_external_cleanup_free_failure_preserves_original_error_and_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/append-external-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xC1]).expect("seed sparse extents");
    }
    let seeded = m.state().mount.read_inode(ino).expect("raw seeded");
    assert_eq!(ext4::parse_extent_header(&seeded.i_block).expect("extent header").depth, 1);

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_data_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.append_block(ino, &vec![0xC2; bs as usize]).expect_err("append data write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
}

#[test]
fn append_inline_inode_failure_cleanup_free_failure_preserves_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/append-inline-inode-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as usize;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.append_block(ino, &vec![0xD1; bs]).expect_err("inode write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
}

#[test]
fn append_inline_promotion_inode_failure_cleanup_free_failure_preserves_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/append-promotion-inode-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6] {
        m.state().mount.write_at(ino, lb * bs, &[0xD2]).expect("seed sparse extents");
    }
    let seeded = m.state().mount.read_inode(ino).expect("raw seeded");
    assert_eq!(ext4::parse_extent_header(&seeded.i_block).expect("extent header").depth, 0);

    let before_free = m.state().mount.state_free_blocks();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.append_block(ino, &vec![0xD3; bs as usize]).expect_err("inode write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &seeded, before_q.dqb_curspace);
    assert_eq!(ext4::parse_extent_header(&m.state().mount.read_inode(ino).expect("raw after").i_block).expect("extent header").depth, 0);
}

#[test]
fn append_external_inode_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/append-external-inode-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xD4]).expect("seed sparse extents");
    }
    let seeded = m.state().mount.read_inode(ino).expect("raw seeded");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    assert_eq!(ext4::parse_extent_header(&seeded.i_block).expect("extent header").depth, 1);

    let before_free = m.state().mount.state_free_blocks();
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.append_block(ino, &vec![0xD5; bs as usize]).expect_err("inode write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &seeded, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn external_leaf_split_inode_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/leaf-split-inode-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xD6]).expect("seed external sparse extents");
    }
    let seeded = m.state().mount.read_inode(ino).expect("raw seeded");
    assert_eq!(ext4::parse_extent_header(&seeded.i_block).expect("extent header").depth, 1);
    pin_tree_maxes(&disk, &m.state().mount.sb, ino, seeded.generation, &seeded.i_block, m.state().mount.sb.block_size);

    let before_free = m.state().mount.state_free_blocks();
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.write_at(ino, 10 * bs, &[0xD7]).expect_err("inode write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &seeded, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn inline_promotion_metadata_failure_cleanup_free_failure_preserves_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/promotion-metadata-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6] {
        m.state().mount.write_at(ino, lb * bs, &[0xE1]).expect("seed inline sparse extents");
    }
    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    assert_eq!(ext4::parse_extent_header(&before_raw.i_block).expect("extent header").depth, 0);

    m.state().mount.fail_next_extent_block_write_for_tests();
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.write_at(ino, 8 * bs, &[0xE2]).expect_err("metadata write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
    assert_eq!(ext4::parse_extent_header(&m.state().mount.read_inode(ino).expect("raw after").i_block).expect("extent header").depth, 0);
}

#[test]
fn fallocate_partial_alloc_failure_cleanup_free_failure_preserves_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/fallocate-partial-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_alloc_block_after_for_tests(1);
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.fallocate_inode(ino, 0, bs * 2, false).expect_err("second allocation fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
}

#[test]
fn external_leaf_split_metadata_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/leaf-split-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xF1]).expect("seed external sparse extents");
    }
    let seeded = m.state().mount.read_inode(ino).expect("raw seeded");
    assert_eq!(ext4::parse_extent_header(&seeded.i_block).expect("extent header").depth, 1);
    pin_tree_maxes(&disk, &m.state().mount.sb, ino, seeded.generation, &seeded.i_block, m.state().mount.sb.block_size);

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_extent_block_write_after_for_tests(1);
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.write_at(ino, 10 * bs, &[0xF2]).expect_err("left metadata rewrite fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &before_raw, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn depth_two_metadata_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/depth-two-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    force_depth_two_tree(&disk, &m, ino, bs);
    let seeded = m.state().mount.read_inode(ino).expect("raw seeded");
    pin_tree_maxes(&disk, &m.state().mount.sb, ino, seeded.generation, &seeded.i_block, m.state().mount.sb.block_size);

    let before_free = m.state().mount.state_free_blocks();
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_extent_block_write_after_for_tests(2);
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.write_at(ino, 18 * bs, &[0xA3]).expect_err("depth-two metadata write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_inode_quota_unchanged_after_cleanup_abort(&m, &sb, qid, ino, before_free, &seeded, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}

#[test]
fn punch_rebuild_metadata_failure_frees_replacement_leaf_and_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-rebuild-metadata-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8, 10] {
        m.state().mount.write_at(ino, lb * bs, &[0xF3]).expect("seed external sparse extents");
    }
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    assert_eq!(ext4::parse_extent_header(&before_raw.i_block).expect("extent header").depth, 1);
    let before_free = m.state().mount.state_free_blocks();
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_extent_block_write_for_tests();
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
fn external_truncate_inode_failure_after_node_write_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/truncate-external-node-write-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xF4]).expect("seed external sparse extents");
    }
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    assert_eq!(ext4::parse_extent_header(&before_raw.i_block).expect("extent header").depth, 1);
    let before_free = m.state().mount.state_free_blocks();
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().mount.truncate_inode(ino, 7 * bs).expect_err("inode write fails after node update is staged");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}
