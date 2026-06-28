//! Validate the `csum` module against mke2fs's own stored checksums
//! in `mini.img` (metadata_csum + metadata_csum_seed + 64bit, 1 KiB
//! blocks, 256-byte inodes). If our crc32c reproduction matches the
//! values mke2fs wrote, the algorithm is Linux-correct and safe to
//! stamp on writes.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn inode_csum_reproduces_root() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    // Root inode (2) raw bytes; mke2fs stamped checksum 0x3201dd21.
    let (raw, _off) = m.read_inode_bytes(2).unwrap();
    let lo = u16::from_le_bytes([raw[0x7C], raw[0x7D]]);
    let hi = u16::from_le_bytes([raw[0x82], raw[0x83]]);
    let stored = ((hi as u32) << 16) | lo as u32;
    let computed = ext4::csum::inode_csum(&m.sb, 2, &raw);
    assert_eq!(computed, stored, "inode csum matches mke2fs for root inode");
    assert_eq!(stored, 0x3201_dd21, "pinned mke2fs value");
}

#[test]
fn stamp_inode_csum_is_idempotent() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let (mut raw, _off) = m.read_inode_bytes(2).unwrap();
    // Corrupt the stored csum, re-stamp, and confirm it heals back.
    raw[0x7C] ^= 0xFF;
    raw[0x82] ^= 0xFF;
    ext4::csum::stamp_inode_csum(&m.sb, 2, &mut raw);
    let lo = u16::from_le_bytes([raw[0x7C], raw[0x7D]]);
    let hi = u16::from_le_bytes([raw[0x82], raw[0x83]]);
    assert_eq!(((hi as u32) << 16) | lo as u32, 0x3201_dd21);
}

#[test]
fn group_desc_csum_reproduces() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let dsize = ext4::desc_size_for(&m.sb) as usize;
    // Read the GDT block (block 2 for 1 KiB images: sb@blk1, gdt@blk2).
    let gdt = m.read_meta_byte_range(m.gdt_byte_offset(), dsize).unwrap();
    let stored = u16::from_le_bytes([gdt[0x1E], gdt[0x1F]]);
    let computed = ext4::csum::group_desc_csum(&m.sb, 0, &gdt);
    assert_eq!(computed, stored, "bg_checksum matches mke2fs");
    assert_eq!(stored, 0x73ab, "pinned mke2fs value");
}

#[test]
fn block_and_inode_bitmap_csum_reproduce() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let gd = m.group_desc(0).unwrap();
    let bs = m.sb.block_size as usize;
    let bbm = m.read_meta_byte_range(gd.block_bitmap * bs as u64, bs).unwrap();
    let ibm = m.read_meta_byte_range(gd.inode_bitmap * bs as u64, bs).unwrap();
    let bcsum = ext4::csum::bitmap_csum(&m.sb, &bbm, m.sb.blocks_per_group);
    let icsum = ext4::csum::bitmap_csum(&m.sb, &ibm, m.sb.inodes_per_group);
    assert_eq!(bcsum, 0x3e3a_c7e4, "block bitmap csum matches dumpe2fs");
    assert_eq!(icsum, 0x3af8_2299, "inode bitmap csum matches dumpe2fs");
}

#[test]
fn superblock_csum_reproduces() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let sb_bytes = m.read_meta_byte_range(1024, 1024).unwrap();
    let stored = u32::from_le_bytes([sb_bytes[0x3FC], sb_bytes[0x3FD], sb_bytes[0x3FE], sb_bytes[0x3FF]]);
    assert_eq!(ext4::csum::superblock_csum(&sb_bytes), stored, "s_checksum matches mke2fs");
}

#[test]
fn dirent_csum_reproduces_root_dir_block() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let root = m.read_inode(2).unwrap();
    let blk = m.read_file_block(&root, 0).unwrap();
    let bs = blk.len();
    let stored = u32::from_le_bytes([blk[bs - 4], blk[bs - 3], blk[bs - 2], blk[bs - 1]]);
    // generation 0 for the root inode (confirmed via debugfs).
    let computed = ext4::csum::dirent_csum(&m.sb, 2, 0, &blk);
    assert_eq!(computed, stored, "dir block tail csum matches mke2fs");
}
