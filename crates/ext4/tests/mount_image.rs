//! P6-06 integration: parse a real mke2fs-built image.
//!
//! Image at `tests/mini.img` is 1 MiB, 1 KiB blocks, no
//! has_journal, default ext4 features (extents on), one
//! file `hello.txt` containing `hello-from-ext4-mini\n` at
//! inode 12. Built via:
//!
//!   dd if=/dev/zero of=mini.img bs=1M count=1
//!   mkfs.ext4 -F -O ^has_journal -L oxide mini.img
//!   debugfs -w -R 'write hello.txt hello.txt' mini.img
//!
//! This test verifies the full chain: superblock parse, GDT
//! parse, root inode read, root dir lookup, target inode read,
//! file data block read.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, KResult, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini.img");
const BLOCK_SIZE: u32 = 512;  // backing-block size; ext4 fs's own block_size is 1024.

/// Wrap MemDisk in a BlockDevice that exposes raw 512-byte sectors,
/// preloaded with IMAGE bytes.
fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (BLOCK_SIZE as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    // MemDisk doesn't expose a raw write-bytes API; fake it via
    // submit_sync with a Write request covering the whole image.
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: 0,
        len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("memdisk write");
    disk
}

#[test]
fn open_parses_superblock() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    assert_eq!(m.sb.magic, ext4::EXT4_SUPER_MAGIC);
    assert_eq!(m.sb.block_size, 1024, "mke2fs picked 1 KiB blocks for 1 MiB fs");
    assert!(m.sb.has_extents(), "ext4 default has extents");
}

#[test]
fn root_inode_is_directory() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let root = m.read_inode(2).expect("read root");
    assert!(root.is_dir(), "inode 2 is /");
}

#[test]
fn lookup_path_hello_txt() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let ino = m.lookup_path(b"/hello.txt").expect("lookup");
    assert!(ino > 11, "inode num for first user file > reserved (11)");
    let ino_struct = m.read_inode(ino).expect("read");
    assert!(ino_struct.is_reg(), "hello.txt is a regular file");
    let n: u64 = "hello-from-ext4-mini\n".len() as u64;
    assert_eq!(ino_struct.size, n, "file size matches debugfs payload");
}

#[test]
fn read_file_block_returns_payload() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let ino = m.lookup_path(b"/hello.txt").expect("lookup");
    let inode = m.read_inode(ino).expect("read");
    let blk = m.read_file_block(&inode, 0).expect("read blk0");
    let want = b"hello-from-ext4-mini\n";
    assert_eq!(&blk[..want.len()], want, "first bytes of blk 0 = file content");
}

#[test]
fn lookup_path_missing_returns_notfound() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let err = m.lookup_path(b"/no-such-file").err().expect("err");
    assert_eq!(err, ext4::MountError::NotFound);
}
