//! Activating a swapfile marks the INODE, so the generic gate above the
//! filesystem is the thing that refuses to move a live swap area's blocks.
//! The flag is the only record that a file is a swap area — there is no
//! filesystem-private copy that could disagree with it — and it is released
//! when the last reference to the direct block-device view goes away.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
/// A swap area is whole pages of fully-mapped, written blocks.
const SWAP_BYTES: u64 = 2 * hal::PAGE_SIZE_BYTES;
const FILL_BYTE: u8 = 0x5a;
const FALLOC_ALLOCATE_RANGE: u32 = 0;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// A mounted image plus one fully-written, page-aligned regular file wrapped as
/// a live VFS inode — the shape `swapon` hands to the backing builder.
fn swap_candidate() -> (Arc<ext4::rootfs::Ext4Mount>, Arc<vfs::SuperBlock>, vfs::InodeRef) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs.clone(), root, 0x5341_5000, String::from("ext4"));
    let ino = m.state().mount.create_file(2, b"swap.img", 0o600, 0, 0).unwrap();
    m.state().mount.write_at(ino, 0, &alloc::vec![FILL_BYTE; SWAP_BYTES as usize]).unwrap();
    let inode = m.state().wrap_file(ino).expect("wrap the swap candidate");
    inode.set_size(SWAP_BYTES);
    (m, sb, inode)
}

#[test]
fn activation_sets_the_generic_swapfile_flag_and_deactivation_clears_it() {
    let (_m, _sb, inode) = swap_candidate();
    assert!(!inode.is_swapfile(), "a plain file carries no swap claim");

    let backing = ext4::rootfs::swapfile_backing(&inode).expect("activate");
    assert!(inode.is_swapfile());
    assert_ne!(inode.i_flags() & vfs::S_SWAPFILE, 0,
        "the claim is the generic i_flags bit the VFS ladder reads, not a private one");

    drop(backing);
    assert!(!inode.is_swapfile(), "swapoff releases the claim");
    assert_eq!(inode.i_flags() & vfs::S_SWAPFILE, 0);
}

#[test]
fn a_second_activation_of_a_live_swapfile_is_refused() {
    let (_m, _sb, inode) = swap_candidate();
    let _backing = ext4::rootfs::swapfile_backing(&inode).expect("first activation");
    assert_eq!(ext4::rootfs::swapfile_backing(&inode).err(), Some(vfs::VfsError::Ebusy),
        "one swap area per inode");
}

#[test]
fn a_block_moving_operation_on_a_live_swapfile_is_etxtbsy() {
    let (_m, _sb, inode) = swap_candidate();
    let _backing = ext4::rootfs::swapfile_backing(&inode).expect("activate");
    // The generic ladder answers these before the filesystem is reached; the
    // backend gate below it must agree rather than report a different failure
    // to a caller that raced activation.
    assert_eq!(inode.fallocate(FALLOC_ALLOCATE_RANGE, 0, SWAP_BYTES),
        Err(vfs::VfsError::Etxtbsy));
    assert_eq!(inode.truncate(0), Err(vfs::VfsError::Etxtbsy));
}

#[test]
fn the_file_is_mutable_again_once_the_area_is_gone() {
    let (_m, _sb, inode) = swap_candidate();
    let backing = ext4::rootfs::swapfile_backing(&inode).expect("activate");
    assert!(inode.truncate(0).is_err());
    drop(backing);
    inode.truncate(0).expect("swapoff hands the blocks back to the filesystem");
    assert_eq!(inode.size(), 0);
}
