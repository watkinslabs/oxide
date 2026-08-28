//! P7b-02 integration: append + read-back against mini.img.
//!
//! Append one fs-block of fresh data to /hello.txt, then re-open
//! the FS (same backing disk) and verify the new logical block is
//! readable + matches what we wrote.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("../mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// Build a deliberately fragmented logical layout without relying on the
/// allocator defeating regular-file preallocation.  Linux is allowed to keep
/// sequential appends contiguous, so tests that need a deep extent tree must
/// introduce logical holes explicitly.
fn fragmented_file(m: &ext4::Mount, ino: u32, bs: usize, logicals: &[u32])
    -> std::vec::Vec<std::vec::Vec<u8>>
{
    for &logical in logicals {
        m.fallocate_inode(ino, logical as u64 * bs as u64, bs as u64, false).unwrap();
    }
    let payloads: std::vec::Vec<std::vec::Vec<u8>> = logicals.iter()
        .enumerate().map(|(i, _)| std::vec![i as u8; bs]).collect();
    for (&logical, payload) in logicals.iter().zip(payloads.iter()) {
        m.write_at(ino, logical as u64 * bs as u64, payload).unwrap();
    }
    payloads
}

fn read_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32) -> std::vec::Vec<u8> {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Read,
        start_block: fs_lba * sectors as u64,
        len_blocks: sectors,
        buffer: std::vec![0u8; fs_bs as usize], ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

fn write_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32, buffer: std::vec::Vec<u8>) {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: fs_lba * sectors as u64,
        len_blocks: sectors,
        buffer, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
}

fn inline_idx_lba(i_block: &[u8], idx: usize) -> u64 {
    let off = 12 + idx * 12;
    let leaf_lo = u32::from_le_bytes([i_block[off + 4], i_block[off + 5], i_block[off + 6], i_block[off + 7]]);
    let leaf_hi = u16::from_le_bytes([i_block[off + 8], i_block[off + 9]]);
    ((leaf_hi as u64) << 32) | leaf_lo as u64
}

fn slice_idx_lba(buf: &[u8], idx: usize) -> u64 {
    let off = 12 + idx * 12;
    let leaf_lo = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
    let leaf_hi = u16::from_le_bytes([buf[off + 8], buf[off + 9]]);
    ((leaf_hi as u64) << 32) | leaf_lo as u64
}

fn extent_header_entries(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[2], buf[3]])
}

fn extent_header_depth(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[6], buf[7]])
}

fn force_external_extent_maxes(disk: &Arc<dyn BlockDevice>, sb: &ext4::Superblock,
                               ino: u32, gen: u32, fs_lba: u64, fs_bs: u32, max: u16) {
    let mut buf = read_fs_block(disk, fs_lba, fs_bs);
    let entries = extent_header_entries(&buf) as usize;
    let depth = extent_header_depth(&buf);
    buf[4..6].copy_from_slice(&max.to_le_bytes());
    // Poking eh_max invalidates the block's metadata_csum tail; re-stamp it so
    // the on-disk block stays consistent (mirrors what a real e2fsprogs tool
    // would do). Without this, read-side verify correctly rejects the block.
    ext4::csum::stamp_extent_block_csum(sb, ino, gen, &mut buf);
    write_fs_block(disk, fs_lba, fs_bs, buf.clone());

    if depth > 0 {
        for i in 0..entries {
            force_external_extent_maxes(disk, sb, ino, gen, slice_idx_lba(&buf, i), fs_bs, max);
        }
    }
}

fn force_tree_external_maxes(disk: &Arc<dyn BlockDevice>, sb: &ext4::Superblock,
                             ino: u32, gen: u32, i_block: &[u8], fs_bs: u32, max: u16) {
    let depth = extent_header_depth(i_block);
    if depth == 0 {
        return;
    }
    for i in 0..extent_header_entries(i_block) as usize {
        force_external_extent_maxes(disk, sb, ino, gen, inline_idx_lba(i_block, i), fs_bs, max);
    }
}

fn leaf_extent_blocks(buf: &[u8]) -> std::vec::Vec<u32> {
    let entries = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let mut out = std::vec::Vec::with_capacity(entries);
    for i in 0..entries {
        let off = 12 + i * 12;
        out.push(u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]));
    }
    out
}


#[path = "tests/basic.rs"]
mod basic;
#[path = "tests/sparse.rs"]
mod sparse;
#[path = "tests/lifecycle.rs"]
mod lifecycle;
#[path = "tests/integrity.rs"]
mod integrity;
#[path = "tests/remount.rs"]
mod remount;
