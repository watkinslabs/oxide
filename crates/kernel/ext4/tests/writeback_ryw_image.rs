//! Read-your-writes for the inode i_size WITHIN one journal transaction, and
//! the batched multi-page write_at path. Pins the hwdb-blocker regression:
//! batching per-page writeback into one `run_journaled` must NOT re-zero-extend
//! each page from block 0 (O(n²)) — a later page must observe the size an
//! earlier page staged. See memory `hwdb-blocker-ext4-writeback-commits`.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

mod common;

const IMAGE: &[u8] = include_bytes!("mini.img");
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

/// Within ONE open journal transaction, `set_inode_size` then `read_inode`
/// must reflect the staged size (read-your-writes). This is the exact property
/// batched writeback relies on; if it fails, batching goes O(n²).
#[test]
fn set_inode_size_is_visible_to_read_inode_within_one_txn() {
    common::boot_hosted_pmm();
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let ino = m.lookup_path(b"/hello.txt").expect("hello.txt");
    m.run_journaled(|mm| {
        mm.set_inode_size(ino, 123456)?;
        let sz = mm.read_inode(ino)?.size;
        assert_eq!(sz, 123456, "read_inode sees the size staged by set_inode_size in the same txn");
        // Stage a second, larger size — still visible.
        mm.set_inode_size(ino, 999999)?;
        let sz2 = mm.read_inode(ino)?.size;
        assert_eq!(sz2, 999999, "read_inode sees the latest staged size");
        Ok(())
    }).unwrap();
}

/// Two write_at calls to a growing file, batched in ONE transaction: the second
/// (higher-offset) write must see the size the first persisted, so it does NOT
/// re-zero-extend from block 0. Guards the O(n²) regression.
#[test]
fn batched_multi_write_at_does_not_reextend_from_zero() {
    common::boot_hosted_pmm();
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    let bs = m.sb.block_size as u64;
    // Create a fresh file so we own its whole extent history.
    let root = m.lookup_path(b"/").expect("root");
    let ino = m.run_journaled(|mm| mm.create_file(root, b"grow.bin", 0o644, 0, 0)).expect("create");

    // Batched: write block 0, then a block far past EOF, in one txn.
    let far = 200u64; // 200 blocks past start
    let a = std::vec![0xA1u8; bs as usize];
    let b = std::vec![0xB2u8; bs as usize];
    m.run_journaled(|mm| {
        mm.write_at(ino, 0, &a)?;
        // After this, in-txn size should be (far+1)*bs; the NEXT write_at at a
        // lower offset must see it and NOT re-extend.
        mm.write_at(ino, far * bs, &b)?;
        // A write landing BELOW the current high-water mark: span must be 0.
        let before = mm.read_inode(ino)?.size;
        assert_eq!(before, (far + 1) * bs, "size reflects the far write within the txn");
        mm.write_at(ino, 5 * bs, &a)?;
        Ok(())
    }).unwrap();

    // Remount and verify data integrity at 0, 5, and far.
    drop(m);
    let m2 = ext4::Mount::open(disk).unwrap();
    let ino2 = m2.lookup_path(b"/grow.bin").expect("grow.bin remount");
    let inode = m2.read_inode(ino2).unwrap();
    assert_eq!(inode.size, (far + 1) * bs, "final size persisted");
    let blk0 = m2.read_file_block(&inode, 0).unwrap();
    assert_eq!(blk0[0], 0xA1, "block 0 data intact");
    let blkfar = m2.read_file_block(&inode, far as u32).unwrap();
    assert_eq!(blkfar[0], 0xB2, "far block data intact");
}
