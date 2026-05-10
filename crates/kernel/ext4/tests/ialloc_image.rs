//! P7b-04 integration: create_file + unlink against mini.img.

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
fn create_file_visible_to_lookup() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"newfile", 0o644).unwrap();
    let got = m.lookup_path(b"/newfile").unwrap();
    assert_eq!(got, n);
    let inode = m.read_inode(n).unwrap();
    assert!(inode.is_reg());
    assert_eq!(inode.size, 0);
    assert_eq!(inode.links_count, 1);
}

#[test]
fn create_then_append_then_read() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"data.bin", 0o644).unwrap();
    let bs = m.sb.block_size as usize;
    let payload: std::vec::Vec<u8> = (0..bs).map(|i| (i & 0xFF) as u8).collect();
    m.append_block(n, &payload).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, bs as u64);
    let blk = m.read_file_block(&inode, 0).unwrap();
    assert_eq!(blk, payload);
}

#[test]
fn unlink_frees_inode_and_blocks() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let pre_blocks = m.state_free_blocks();
    let pre_inodes = m.state_free_inodes();
    let n = m.create_file(2, b"toremove", 0o644).unwrap();
    let bs = m.sb.block_size as usize;
    m.append_block(n, &std::vec![0u8; bs]).unwrap();
    m.append_block(n, &std::vec![0u8; bs]).unwrap();
    m.unlink(2, b"toremove").unwrap();
    assert_eq!(m.state_free_blocks(), pre_blocks, "data blocks returned to pool");
    assert_eq!(m.state_free_inodes(), pre_inodes, "inode returned to pool");
    assert!(m.lookup_path(b"/toremove").is_err());
}

#[test]
fn create_persists_across_remount() {
    let disk = build_disk();
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        m.create_file(2, b"persist", 0o644).unwrap();
    }
    let m2 = ext4::Mount::open(disk).unwrap();
    assert!(m2.lookup_path(b"/persist").is_ok(), "create survived remount");
}
