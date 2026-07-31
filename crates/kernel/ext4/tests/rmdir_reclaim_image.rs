//! A3 (ext4fix §4.1/§4.2): rmdir reclaims the victim directory's data blocks +
//! inode, drops its group's used-dirs count, and decrements the PARENT link
//! count on-disk — persisted across a remount.
//!
//! Before A3, rmdir only removed the dirent + cleared the inode bit: the dir's
//! data block(s) leaked and the parent's nlink drop lived only in the in-core
//! inode (never written), so every mkdir/rmdir cycle drifted the on-disk
//! metadata upward. Image: mini-j.img (journaled).

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const ROOT_INO: u32 = 2;

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

#[test]
fn rmdir_frees_blocks_inode_and_parent_nlink() {
    let disk = shared_disk();
    let m = ext4::Mount::open(disk.clone()).expect("mount");

    let nlink0 = m.read_inode(ROOT_INO).unwrap().links_count;
    let free_blk0 = m.state_free_blocks();
    let free_ino0 = m.state_free_inodes();

    let rd = m.create_dir(ROOT_INO, b"rd", 0o755, 0, 0).expect("mkdir");
    assert_eq!(m.read_inode(ROOT_INO).unwrap().links_count, nlink0 + 1, "mkdir bumps parent nlink");
    assert!(m.state_free_blocks() < free_blk0, "mkdir consumes a data block");
    assert_eq!(m.state_free_inodes(), free_ino0 - 1, "mkdir consumes an inode");

    m.rmdir(ROOT_INO, b"rd").expect("rmdir");
    assert_eq!(m.read_inode(ROOT_INO).unwrap().links_count, nlink0, "rmdir restores parent nlink");
    assert_eq!(m.state_free_blocks(), free_blk0, "rmdir frees the dir's data block (no leak)");
    assert_eq!(m.state_free_inodes(), free_ino0, "rmdir frees the inode");
    assert_eq!(m.read_inode(rd).unwrap().links_count, 0, "victim inode cleared");
    assert!(m.lookup_path(b"/rd").is_err(), "dirent removed");

    // Persisted: remount the same disk; the parent nlink drop survived.
    drop(m);
    let m2 = ext4::Mount::open(disk).expect("remount");
    assert_eq!(m2.read_inode(ROOT_INO).unwrap().links_count, nlink0, "remount: parent nlink persisted");
    assert!(m2.lookup_path(b"/rd").is_err(), "remount: dir gone");
}
