//! P7b-06 integration: open a real journaled ext4 image, parse
//! its journal SB via Mount::recover_journal. Image is built
//! clean by mkfs.ext4, so replay is a no-op (s_start = 0); the
//! test verifies the parser can locate + decode the journal SB
//! through the journal inode's extents.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
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
fn journaled_image_mounts_clean() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    assert!(m.sb.has_extents());
    assert_ne!(m.sb.journal_inum, 0, "image has a journal inode (s_journal_inum)");
    // recover_journal() returns None for a clean log (INCOMPAT_RECOVER off).
    // Calling it must not error.
    let _ = m.recover_journal().unwrap();
}

#[test]
fn journaled_image_supports_writes() {
    // Even with a journal present + recover support running, the
    // ext4 RW path (alloc_block + create_file + …) must continue
    // to work. Replay is no-op, then we exercise the live writes.
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"jt.bin", 0o644).unwrap();
    let bs = m.sb.block_size as usize;
    m.append_block(n, &std::vec![0xEE; bs]).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, bs as u64);
    let blk = m.read_file_block(&inode, 0).unwrap();
    assert_eq!(blk, std::vec![0xEE; bs]);
}
