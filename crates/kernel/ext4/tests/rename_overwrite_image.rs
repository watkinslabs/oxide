//! P7b rename-overwrite nlink authority: a plain rename that OVERWRITES an
//! existing destination must drop the replaced target's in-memory `st_nlink`
//! (Linux `vfs_rename`), mirroring the unlink path's authority now that the
//! dcache `d_unlink` no longer touches nlink. RENAME_EXCHANGE (the trait
//! `exchange`) must NOT drop — both inodes survive.
//!
//! Image: mini.img (root dir = inode 2, no journal). We create two regular
//! files in the root, hold the cached `Arc` for the destination, rename the
//! source over it, and assert the replaced inode's nlink dropped to 0.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{CreateCtx, SuperBlock};

const MINI: &[u8] = include_bytes!("mini.img");
const BLOCK_SIZE: u32 = 512;

fn disk() -> Arc<dyn BlockDevice> {
    let cap = (MINI.len() as u64) / (BLOCK_SIZE as u64);
    let d: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: MINI.to_vec() };
    d.submit_sync(&mut req).expect("memdisk write");
    d
}

/// Open the fixture as an `Ext4Mount` and back-stamp a live `SuperBlock` so
/// inode lookups populate the per-SB icache (the `ilookup` rename relies on).
fn mount() -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk()).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = SuperBlock::for_backend(fs, root, 0xE471_0001, String::from("ext4"));
    (m, sb)
}

#[test]
fn rename_overwrite_drops_replaced_target_nlink() {
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let _src = root.create_child("rsrc", 0o644, &CreateCtx::root()).expect("create rsrc");
    let dst = root.create_child("rdst", 0o644, &CreateCtx::root()).expect("create rdst");
    assert_eq!(dst.nlink(), 1, "fresh dest starts with one link");

    let fs: Arc<dyn FileSystem> = m.clone();
    fs.rename("/rsrc", "/rdst").expect("rename overwrite");

    // The replaced (cached) destination inode lost its link.
    assert_eq!(dst.nlink(), 0, "replaced destination in-memory nlink dropped to 0");
    // Source name gone; destination name now resolves on disk.
    assert!(m.state().lookup_path(b"/rsrc").is_none(), "source name removed");
    assert!(m.state().lookup_path(b"/rdst").is_some(), "destination name present");
}

#[test]
fn exchange_does_not_drop_either_nlink() {
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let a = root.create_child("xa", 0o644, &CreateCtx::root()).expect("create xa");
    let b = root.create_child("xb", 0o644, &CreateCtx::root()).expect("create xb");
    assert_eq!((a.nlink(), b.nlink()), (1, 1));

    let fs: Arc<dyn FileSystem> = m.clone();
    fs.exchange("/xa", "/xb").expect("exchange");

    // Neither inode lost a link: RENAME_EXCHANGE only swaps names.
    assert_eq!(a.nlink(), 1, "exchange survivor a keeps its link");
    assert_eq!(b.nlink(), 1, "exchange survivor b keeps its link");
    assert!(m.state().lookup_path(b"/xa").is_some(), "name xa still present");
    assert!(m.state().lookup_path(b"/xb").is_some(), "name xb still present");
}
