extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

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

fn read_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32) -> std::vec::Vec<u8> {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Read, start_block: fs_lba * sectors as u64,
        len_blocks: sectors, buffer: std::vec![0u8; fs_bs as usize], ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

fn write_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32, buffer: std::vec::Vec<u8>) {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest { op: BlockOp::Write, start_block: fs_lba * sectors as u64, len_blocks: sectors, buffer, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
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

fn quota_space_matches_i_blocks(m: &ext4::rootfs::Ext4Mount, sb: &SuperBlock, ino: u32, qid: Kqid) -> u64 {
    let raw = m.state().mount.read_inode(ino).expect("read raw inode");
    let q = vfs::quota_getquota(sb, qid).expect("quota record");
    assert_eq!(q.dqb_curspace, raw.i_blocks as u64 * 512);
    q.dqb_curspace
}

#[test]
fn vfs_setxattr_edquot_returns_error_and_does_not_cache_value() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/vfs-xattr-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    vfs::quota_setquota(&sb, qid, MemDqblk {
        dqb_bhardlimit: 1, dqb_ihardlimit: 100,
        dqb_curspace: before_q.dqb_curspace, dqb_curinodes: before_q.dqb_curinodes,
        ..MemDqblk::new()
    }).expect("set block hardlimit below external xattr block");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let err = inode.setxattr("user.big", vec![0xAB; 200], false, false).expect_err("setxattr must fail");

    assert_eq!(err, vfs::XattrError::Fs(vfs::VfsError::Edquot));
    assert_eq!(inode.getxattr("user.big"), Err(vfs::XattrError::NotFound));
    assert_eq!(m.state().mount.state_free_blocks(), before_free, "EDQUOT setxattr must not leak a block");
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after").i_blocks, before_raw.i_blocks);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn external_extent_edquot_precharge_does_not_allocate_data_or_meta() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/extent-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0x5a]).expect("seed sparse extent");
    }
    let raw = m.state().mount.read_inode(ino).expect("raw after seed");
    assert_eq!(ext4::parse_extent_header(&raw.i_block).expect("extent header").depth, 1);
    pin_tree_maxes(&disk, &m.state().mount.sb, ino, raw.generation, &raw.i_block, m.state().mount.sb.block_size);

    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before limit");
    vfs::quota_setquota(&sb, qid, MemDqblk {
        dqb_bhardlimit: before_q.dqb_curspace, dqb_ihardlimit: 100,
        dqb_curspace: before_q.dqb_curspace, dqb_curinodes: before_q.dqb_curinodes,
        ..MemDqblk::new()
    }).expect("set block hardlimit at current usage");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before EDQUOT");
    let err = m.state().mount.write_at(ino, 10 * bs, &[0x33]).expect_err("write must fail");

    assert!(matches!(err, ext4::MountError::Quota(vfs::VfsError::Edquot)));
    assert_eq!(m.state().mount.state_free_blocks(), before_free, "EDQUOT write must not allocate data/meta blocks");
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after EDQUOT").i_blocks, before_raw.i_blocks);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn truncate_releases_project_block_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/truncate-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0x5a; (bs * 4) as usize]).expect("seed file data");
    let before = quota_space_matches_i_blocks(&m, &sb, ino, qid);

    m.state().mount.truncate_inode(ino, bs).expect("truncate releases blocks");

    let raw = m.state().mount.read_inode(ino).expect("raw after truncate");
    let after = quota_space_matches_i_blocks(&m, &sb, ino, qid);
    assert_eq!(raw.size, bs);
    assert!(after < before);
}

#[test]
fn punch_hole_releases_project_block_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0x6b; (bs * 5) as usize]).expect("seed file data");
    let before = quota_space_matches_i_blocks(&m, &sb, ino, qid);

    m.state().mount.punch_hole_inode(ino, bs, bs * 2).expect("punch releases blocks");

    let raw = m.state().mount.read_inode(ino).expect("raw after punch");
    let after = quota_space_matches_i_blocks(&m, &sb, ino, qid);
    assert_eq!(raw.size, bs * 5);
    assert!(after < before);
}

#[test]
fn truncate_inode_write_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/truncate-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0x5c; (bs * 4) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before truncate failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before truncate failure");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().mount.truncate_inode(ino, bs).expect_err("injected inode write failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after truncate failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after truncate failure");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn punch_inode_write_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0x6d; (bs * 5) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before punch failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before punch failure");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().mount.punch_hole_inode(ino, bs, bs * 2).expect_err("injected inode write failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after punch failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after punch failure");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn xattr_shrink_inode_write_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/xattr-shrink-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;

    inode.setxattr("user.big", vec![0xC3; 300], false, false).expect("create external xattr");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before xattr shrink failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before xattr shrink failure");

    m.state().mount.fail_next_inode_write_for_tests();
    let err = inode.removexattr("user.big").expect_err("injected inode write failure");

    assert_eq!(err, vfs::XattrError::Fs(vfs::VfsError::Eio));
    let after_raw = m.state().mount.read_inode(ino).expect("raw after xattr shrink failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after xattr shrink failure");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
    assert_eq!(inode.getxattr("user.big").expect("cache remains unchanged"), vec![0xC3; 300]);
}

#[test]
fn truncate_free_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/truncate-free-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0x7a; (bs * 4) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before truncate free failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before truncate free failure");

    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.truncate_inode(ino, bs).expect_err("injected block-free failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after truncate free failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after truncate free failure");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn punch_free_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/punch-free-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    m.state().mount.write_at(ino, 0, &vec![0x7b; (bs * 5) as usize]).expect("seed file data");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before punch free failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before punch free failure");

    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.punch_hole_inode(ino, bs, bs * 2).expect_err("injected block-free failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after punch free failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after punch free failure");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn xattr_shrink_free_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/xattr-free-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;

    inode.setxattr("user.big", vec![0xD4; 300], false, false).expect("create external xattr");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before xattr free failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before xattr free failure");

    m.state().mount.fail_next_free_block_for_tests();
    let err = inode.removexattr("user.big").expect_err("injected block-free failure");

    assert_eq!(err, vfs::XattrError::Fs(vfs::VfsError::Eio));
    let after_raw = m.state().mount.read_inode(ino).expect("raw after xattr free failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after xattr free failure");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
    assert_eq!(inode.getxattr("user.big").expect("cache remains unchanged"), vec![0xD4; 300]);
}

#[test]
fn inline_write_alloc_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/inline-alloc-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before alloc failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before alloc failure");

    m.state().mount.fail_next_alloc_block_for_tests();
    let err = m.state().mount.write_at(ino, 0, &vec![0x8e; bs as usize]).expect_err("injected alloc failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after alloc failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after alloc failure");
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn inline_promotion_extent_write_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/inline-promote-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    for lb in [0u64, 2, 4, 6] {
        m.state().mount.write_at(ino, lb * bs, &[0x91]).expect("seed inline sparse extent");
    }
    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before extent write failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before extent write failure");

    m.state().mount.fail_next_extent_block_write_for_tests();
    let err = m.state().mount.write_at(ino, 8 * bs, &[0x92]).expect_err("injected extent metadata write failure");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after extent write failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after extent write failure");
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn fallocate_edquot_does_not_allocate_unwritten_block() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/fallocate-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before limit");
    vfs::quota_setquota(&sb, qid, MemDqblk {
        dqb_bhardlimit: 1, dqb_ihardlimit: 100,
        dqb_curspace: before_q.dqb_curspace, dqb_curinodes: before_q.dqb_curinodes,
        ..MemDqblk::new()
    }).expect("set block hardlimit at current usage");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before EDQUOT");
    let err = m.state().mount.fallocate_inode(ino, 0, bs, false).expect_err("fallocate must fail");

    assert!(matches!(err, ext4::MountError::Quota(vfs::VfsError::Edquot)));
    assert_eq!(m.state().mount.state_free_blocks(), before_free, "EDQUOT fallocate must not allocate a data block");
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after EDQUOT").i_blocks, before_raw.i_blocks);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn fallocate_second_alloc_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/fallocate-second-alloc-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before second alloc failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before second alloc failure");

    m.state().mount.fail_alloc_block_after_for_tests(1);
    let err = m.state().mount.fallocate_inode(ino, 0, bs * 2, false).expect_err("second allocation fails");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after second alloc failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after second alloc failure");
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}

#[test]
fn write_data_flush_failure_rolls_project_quota_back() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/write-data-fail-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before data failure");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before data failure");

    m.state().mount.fail_next_data_write_for_tests();
    let err = m.state().mount.write_at(ino, 0, &vec![0xA5; bs as usize]).expect_err("data flush fails");

    assert_eq!(err, ext4::MountError::BlockIo);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after data failure");
    let after_q = vfs::quota_getquota(&sb, qid).expect("quota after data failure");
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(after_q.dqb_curspace, before_q.dqb_curspace);
}
