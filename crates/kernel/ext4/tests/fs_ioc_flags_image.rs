//! B2 (ext4fix §7.3): FS_IOC_GETFLAGS/SETFLAGS backend — the ext4 inode's
//! on-disk `i_flags` (chattr/lsattr) round-trip through `fileattr_get`/`set`,
//! persist across a remount, only touch the user-modifiable bits (the extent
//! layout flag EXTENTS_FL is preserved), and mirror IMMUTABLE into the in-core
//! VFS `i_flags` for enforcement.
//!
//! Image: mini-j.img (journaled — fileattr_set writes through run_journaled).

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{FileAttr, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

// FS_*_FL == ext4 on-disk i_flags bits.
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_NODUMP_FL:    u32 = 0x0000_0040;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000; // kernel-internal, must be preserved

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_F1A6, String::from("ext4"));
    (m, sb)
}

#[test]
fn chattr_flags_roundtrip_persist_and_preserve() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let inode = m.state().create_at(b"/chattr.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/chattr.txt").expect("lookup");

    // Fresh regular file: EXTENTS_FL set on disk, no chattr user flags visible.
    assert_ne!(m.state().mount.read_inode(ino).unwrap().i_flags & EXT4_EXTENTS_FL, 0,
        "regular file carries EXTENTS_FL");
    assert_eq!(inode.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL), 0,
        "no chattr flags initially");

    // chattr +i +d (immutable + nodump).
    inode.fileattr_set(&FileAttr { flags: FS_IMMUTABLE_FL | FS_NODUMP_FL, ..Default::default() })
        .expect("fileattr_set");
    assert_eq!(inode.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL),
        FS_IMMUTABLE_FL | FS_NODUMP_FL, "get reflects the set flags");
    // Kernel-internal EXTENTS_FL preserved (only user-modifiable bits changed).
    assert_ne!(m.state().mount.read_inode(ino).unwrap().i_flags & EXT4_EXTENTS_FL, 0,
        "EXTENTS_FL preserved across SETFLAGS");
    // In-core VFS inode reflects immutable for enforcement.
    assert_ne!(inode.i_flags() & vfs::S_IMMUTABLE, 0, "S_IMMUTABLE mirrored in-core");

    // Persist across remount.
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let node = m2.state().lookup_inode_any(b"/chattr.txt").expect("lookup after remount");
    assert_eq!(node.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL),
        FS_IMMUTABLE_FL | FS_NODUMP_FL, "remount: chattr flags persisted");

    // chattr -i -d clears them, still preserving EXTENTS_FL.
    node.fileattr_set(&FileAttr::default()).expect("clear");
    assert_eq!(node.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL), 0, "cleared");
    let ino2 = m2.state().mount.lookup_path(b"/chattr.txt").unwrap();
    assert_ne!(m2.state().mount.read_inode(ino2).unwrap().i_flags & EXT4_EXTENTS_FL, 0,
        "EXTENTS_FL still preserved after clear");
}
