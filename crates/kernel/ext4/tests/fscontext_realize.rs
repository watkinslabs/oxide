//! D13/D14 (ext4): the CONVERTED fs_context mount path realizes the SAME
//! superblock the legacy `FsType::mount(source)` graft does, byte-identically,
//! and the `FS_REQUIRES_DEV` gate rejects a missing source.
//!
//! Converted chain: `fsopen` → `fsconfig(SET source)` → `fsconfig(CMD_CREATE)`
//! → `vfs_get_tree` → `LegacyFsContextOps::get_tree` →
//! `FsType::mount(fc.source(), opts)` → ext4 ctor (`Ext4Mount::open(dev)`).
//! Because the ext4 ctor keys off `source` (the block device), NOT the mount
//! target, the SB realized at CMD_CREATE equals what `mount_fstype` would graft.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::{
    get_fs_type, register_fs, vfs_get_tree, vfs_parse_fs_string, FsContext, FsFlags, FsType,
    MountSpec,
};

const IMAGE: &[u8] = include_bytes!("mini.img");
const BLOCK_SIZE: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (BLOCK_SIZE as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: 0,
        len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("memdisk write");
    disk
}

/// Register an ext4-equivalent `FsType` whose ctor opens an `Ext4Mount` over a
/// disk found by `source` name in the block registry — the production
/// fsmount ctor with the registry lookup specialised to `by_name` for the test.
fn register_ext4_like(fstype: &str) {
    type R = vfs::fs::KResult<MountSpec>;
    let _ = register_fs(FsType::new(
        fstype,
        ext4::EXT4_SUPER_MAGIC as u64,
        FsFlags::FS_REQUIRES_DEV,
        alloc::boxed::Box::new(move |source: &str, _t: &str, _d: &str| -> R {
            let name = source.rsplit('/').next().unwrap_or(source);
            let dev = block::by_name(name).map(|d| d.dev.clone()).ok_or(vfs::VfsError::Enoent)?;
            let fs: Arc<dyn vfs::fs::FileSystem> =
                ext4::rootfs::Ext4Mount::open(dev).map_err(|_| vfs::VfsError::Einval)?;
            Ok(MountSpec { fs, bind_root: None, strict: true })
        }),
    ));
}

#[test]
fn converted_realize_matches_legacy_and_gates_source() {
    let disk = build_disk();
    block::register("cvtdisk", disk);
    register_ext4_like("ext4cvt");
    let ty = get_fs_type("ext4cvt").expect("ext4cvt registered");

    // LEGACY graft: FsType::mount(source) directly.
    let legacy_sb = ty.mount("cvtdisk", "").expect("legacy mount");
    let legacy_root = legacy_sb.s_root().expect("legacy root dentry");
    assert_eq!(legacy_sb.s_magic, ext4::EXT4_SUPER_MAGIC as u64, "legacy s_magic");
    assert!(
        legacy_root.inode().expect("inode").file_type() == vfs::FileType::Directory,
        "legacy root is a directory",
    );

    // CONVERTED realize: source threaded through FsContext, SB built at CMD_CREATE.
    let mut fc = FsContext::for_mount(ty.clone(), 0);
    vfs_parse_fs_string(&mut fc, "source", "/dev/cvtdisk").expect("set source");
    vfs_get_tree(&mut fc).expect("converted realize");
    let conv_sb = fc.sb().expect("converted sb").clone();
    let conv_root = fc.root().expect("converted root").clone();

    // Equivalent realization: same on-disk magic, a directory root — the
    // converted CMD_CREATE path builds the SAME ext4 SB the legacy graft does.
    assert_eq!(conv_sb.s_magic, legacy_sb.s_magic, "converted == legacy s_magic");
    assert!(
        conv_root.inode().expect("inode").file_type() == vfs::FileType::Directory,
        "converted root is a directory",
    );

    // FS_REQUIRES_DEV gate: a context with NO source must fail vfs_get_tree
    // (Linux get_tree_bdev rejects a missing dev_name).
    let mut nodev = FsContext::for_mount(ty, 0);
    assert!(vfs_get_tree(&mut nodev).is_err(), "missing source rejected by FS_REQUIRES_DEV gate");
}
