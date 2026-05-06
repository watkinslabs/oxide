//! P7b-01 integration: alloc/free against the real mini.img.
//!
//! mini.img is 1 MiB (1024 blocks × 1 KiB) with one user file
//! `/hello.txt`. Most blocks are free in the single block group,
//! so `alloc_block` must return distinct, in-range blocks; freeing
//! one returns it to the pool; the on-disk superblock + group
//! descriptor counters must persist the change (re-mount + observe
//! same counts).

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
        op: BlockOp::Write,
        start_block: 0,
        len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn alloc_returns_distinct_in_range_blocks() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let total = m.sb.blocks_count_lo as u64;
    let mut got = std::vec::Vec::new();
    for _ in 0..16 {
        let b = m.alloc_block(0).unwrap();
        assert!(b >= m.sb.first_data_block as u64 && b < total, "blk {} OOR", b);
        assert!(!got.contains(&b), "duplicate alloc {}", b);
        got.push(b);
    }
}

#[test]
fn alloc_then_free_round_trips() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let initial = m.state_free_blocks();
    let b = m.alloc_block(0).unwrap();
    assert_eq!(m.state_free_blocks(), initial - 1);
    m.free_block(b).unwrap();
    assert_eq!(m.state_free_blocks(), initial);
    // Free-then-free is a caller bug.
    assert_eq!(m.free_block(b), Err(ext4::MountError::DoubleFree));
}

#[test]
fn counters_persist_across_remount() {
    let disk = build_disk();
    let initial = {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let pre = m.sb.free_blocks_count;
        let _ = m.alloc_block(0).unwrap();
        let _ = m.alloc_block(0).unwrap();
        let _ = m.alloc_block(0).unwrap();
        pre
    };
    let m2 = ext4::Mount::open(disk).unwrap();
    assert_eq!(m2.sb.free_blocks_count, initial - 3,
               "superblock free count survived close+reopen");
    let gd = m2.group_desc(0).unwrap();
    assert!(gd.free_blocks_count <= (initial as u32) - 3);
}

#[test]
fn freed_block_is_reusable() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let a = m.alloc_block(0).unwrap();
    m.free_block(a).unwrap();
    let b = m.alloc_block(0).unwrap();
    // Allocator picks first-clear-bit; the just-freed slot is the
    // lowest-numbered free bit so we should see it again.
    assert_eq!(a, b, "first-clear-bit reuses freed slot");
}
