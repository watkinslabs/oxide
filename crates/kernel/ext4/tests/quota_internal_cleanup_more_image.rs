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
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A7, String::from("ext4"))?;
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

fn force_depth_two_tree(disk: &Arc<dyn BlockDevice>, m: &ext4::rootfs::Ext4Mount, ino: u32, bs: u64) {
    for lb in [0u64, 2, 4, 6, 8] {
        m.state().mount.write_at(ino, lb * bs, &[0xB1]).expect("seed external tree");
    }
    for lb in [10u64, 12, 14, 16] {
        let raw = m.state().mount.read_inode(ino).expect("raw before depth grow");
        pin_tree_maxes(disk, &m.state().mount.sb, ino, raw.generation, &raw.i_block, m.state().mount.sb.block_size);
        m.state().mount.write_at(ino, lb * bs, &[0xB2]).expect("grow depth two tree");
    }
    let raw = m.state().mount.read_inode(ino).expect("depth two raw");
    assert_eq!(ext4::parse_extent_header(&raw.i_block).expect("extent header").depth, 2);
}

#[test]
fn depth_two_parent_right_metadata_failure_cleanup_free_failure_preserves_quota_and_tree() {
    common::boot_hosted_pmm();
    let disk = seeded_quota_disk();
    let (m, sb) = mount_result(disk.clone()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let inode = m.state().create_at(b"/depth-two-parent-right-write-cleanup-free-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;

    force_depth_two_tree(&disk, &m, ino, bs);
    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before");
    let before_q = vfs::quota_getquota(&sb, qid).expect("quota before");
    pin_tree_maxes(&disk, &m.state().mount.sb, ino, before_raw.generation, &before_raw.i_block, m.state().mount.sb.block_size);

    m.state().mount.fail_extent_block_write_after_for_tests(2);
    m.state().mount.fail_next_free_block_for_tests();
    let err = m.state().mount.write_at(ino, 18 * bs, &[0xB3]).expect_err("depth-two parent right metadata write fails");

    assert!(matches!(err, ext4::MountError::BlockIo));
    assert_eq!(m.state().mount.state_free_blocks(), before_free);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(ext4::parse_extent_header(&after_raw.i_block).expect("extent header").depth, 2);
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after").dqb_curspace, before_q.dqb_curspace);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after"), before_map);
}
