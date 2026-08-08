//! `fallocate(2)` COLLAPSE_RANGE / INSERT_RANGE driven through the ext4 inode
//! operation, not the extent primitive underneath it: the mode dispatch has to
//! reach the shift, the ext4-side argument rules have to run before it, and the
//! inode's cached size has to end up where the on-disk size did.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::uapi::{FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE};

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
const FILE_BLOCKS: u32 = 8;
const RANGE_START_BLOCKS: u64 = 2;
const RANGE_LEN_BLOCKS: u64 = 2;
const MISALIGN_BYTES: u64 = 1;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// A mounted image plus a wrapped inode over a file whose block `i` holds the
/// byte `i`, so the post-shift layout reads straight off the block contents.
fn fixture(name: &[u8]) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<vfs::SuperBlock>, vfs::InodeRef, u32, u64) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs.clone(), root, 0x5348_4654, String::from("ext4"));
    let bs = m.state().mount.sb.block_size as u64;
    let ino = m.state().mount.create_file(2, name, 0o644, 0, 0).unwrap();
    for i in 0..FILE_BLOCKS {
        m.state().mount.write_at(ino, i as u64 * bs, &alloc::vec![i as u8; bs as usize]).unwrap();
    }
    let inode = m.state().wrap_file(ino).expect("wrap");
    (m, sb, inode, ino, bs)
}

fn block_tags(m: &ext4::rootfs::Ext4Mount, ino: u32, count: u32) -> std::vec::Vec<u8> {
    let disk_inode = m.state().mount.read_inode(ino).unwrap();
    (0..count).map(|lb| m.state().mount.read_file_block(&disk_inode, lb).unwrap()[0]).collect()
}

#[test]
fn the_collapse_mode_reaches_the_shift() {
    let (m, _sb, inode, ino, bs) = fixture(b"vfs_collapse.bin");
    inode.fallocate(FALLOC_FL_COLLAPSE_RANGE, RANGE_START_BLOCKS * bs, RANGE_LEN_BLOCKS * bs)
        .expect("collapse is served, not refused");
    let want = (FILE_BLOCKS as u64 - RANGE_LEN_BLOCKS) * bs;
    assert_eq!(m.state().mount.read_inode(ino).unwrap().size, want);
    assert_eq!(inode.size(), want, "the cached size follows the on-disk one");
    assert_eq!(block_tags(&m, ino, FILE_BLOCKS - RANGE_LEN_BLOCKS as u32), std::vec![0, 1, 4, 5, 6, 7]);
}

#[test]
fn the_insert_mode_reaches_the_shift() {
    let (m, _sb, inode, ino, bs) = fixture(b"vfs_insert.bin");
    inode.fallocate(FALLOC_FL_INSERT_RANGE, RANGE_START_BLOCKS * bs, RANGE_LEN_BLOCKS * bs)
        .expect("insert is served, not refused");
    let want = (FILE_BLOCKS as u64 + RANGE_LEN_BLOCKS) * bs;
    assert_eq!(m.state().mount.read_inode(ino).unwrap().size, want);
    assert_eq!(inode.size(), want);
    assert_eq!(block_tags(&m, ino, FILE_BLOCKS + RANGE_LEN_BLOCKS as u32),
        std::vec![0, 1, 0, 0, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn a_misaligned_shift_is_rejected_before_anything_moves() {
    let (m, _sb, inode, ino, bs) = fixture(b"vfs_misaligned.bin");
    let before = m.state().mount.read_inode(ino).unwrap().size;
    assert_eq!(inode.fallocate(FALLOC_FL_COLLAPSE_RANGE, MISALIGN_BYTES, bs),
        Err(vfs::VfsError::Einval));
    assert_eq!(inode.fallocate(FALLOC_FL_INSERT_RANGE, bs, bs + MISALIGN_BYTES),
        Err(vfs::VfsError::Einval));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().size, before, "the file is untouched");
    assert_eq!(block_tags(&m, ino, FILE_BLOCKS), std::vec![0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn a_collapse_reaching_eof_is_rejected_rather_than_treated_as_a_truncate() {
    let (m, _sb, inode, ino, bs) = fixture(b"vfs_eof.bin");
    let tail = FILE_BLOCKS as u64 - 1;
    assert_eq!(inode.fallocate(FALLOC_FL_COLLAPSE_RANGE, tail * bs, bs), Err(vfs::VfsError::Einval));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().size, FILE_BLOCKS as u64 * bs);
}

#[test]
fn an_insert_at_or_past_eof_is_rejected() {
    let (m, _sb, inode, ino, bs) = fixture(b"vfs_insert_eof.bin");
    let eof = FILE_BLOCKS as u64 * bs;
    assert_eq!(inode.fallocate(FALLOC_FL_INSERT_RANGE, eof, bs), Err(vfs::VfsError::Einval));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().size, eof);
}
