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
fn iop_rename_overwrite_drops_replaced_target_nlink() {
    // D9: the resolved-parent `i_op->rename` is byte-equivalent to the
    // whole-path `FileSystem::rename` — same overwrite + nlink-drop semantics.
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let src = root.create_child("isrc", 0o644, &CreateCtx::root()).expect("create isrc");
    let dst = root.create_child("idst", 0o644, &CreateCtx::root()).expect("create idst");
    assert_eq!(dst.nlink(), 1);

    root.rename_child("isrc", &root, "idst", 0, &CreateCtx::root()).expect("iop rename overwrite");

    assert_eq!(dst.nlink(), 0, "replaced destination in-memory nlink dropped to 0");
    assert!(m.state().lookup_path(b"/isrc").is_none(), "source name removed");
    let now = root.lookup("idst").expect("idst present");
    assert!(Arc::ptr_eq(&now, &src), "destination name now holds the source inode");
}

#[test]
fn iop_rename_rejects_exchange_whiteout() {
    let (_m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    root.create_child("ix", 0o644, &CreateCtx::root()).expect("create ix");
    assert!(matches!(
        root.rename_child("ix", &root, "iy", vfs::namei::RENAME_EXCHANGE, &CreateCtx::root()),
        Err(vfs::VfsError::Einval)));
    assert!(matches!(
        root.rename_child("ix", &root, "iy", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root()),
        Err(vfs::VfsError::Einval)));
}

#[test]
fn iop_link_child_hardlinks_and_bumps_nlink() {
    // D9/D13: the resolved-parent `i_op->link` is the path link(2)/linkat(2)
    // now take — it journals a `dir_link` for the existing inode under a new
    // name in the parent dir, bumps the inode's in-memory nlink, and the alias
    // resolves on disk to the same ino. EEXIST on a taken name; EPERM on a dir.
    let (m, sb) = mount();
    let root = sb.s_root_inode().expect("root inode");
    let f = root.create_child("lsrc", 0o644, &CreateCtx::root()).expect("create lsrc");
    assert_eq!(f.nlink(), 1);
    let src_ino = f.ino();

    root.link_child(&f, "lalias", &CreateCtx::root()).expect("iop link");

    assert_eq!(f.nlink(), 2, "hardlink bumped in-memory nlink");
    let alias = root.lookup("lalias").expect("alias resolves");
    assert_eq!(alias.ino(), src_ino, "alias is the SAME on-disk inode");
    assert!(m.state().lookup_path(b"/lalias").is_some(), "alias name present on disk");
    assert!(m.state().lookup_path(b"/lsrc").is_some(), "original name still present");

    // EEXIST on a taken name.
    assert!(matches!(root.link_child(&f, "lalias", &CreateCtx::root()), Err(vfs::VfsError::Eexist)));
    // EPERM on a directory source (no fs permits directory hardlinks).
    let d = root.mkdir("ldir", 0o755, &CreateCtx::root()).expect("mkdir ldir");
    assert!(matches!(root.link_child(&d, "dlink", &CreateCtx::root()), Err(vfs::VfsError::Eperm)));
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
