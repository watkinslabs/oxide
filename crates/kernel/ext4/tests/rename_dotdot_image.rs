//! B7 (ext4fix §4.3): a cross-parent directory rename rewrites the moved dir's
//! `..` to the new parent and adjusts both parents' `i_nlink` — persisted across
//! a remount. Before B7 the moved subtree's `..` dangled at the old parent and
//! both parents' link counts drifted every dir move.
//!
//! Image: mini-j.img (journaled).

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const ROOT: u32 = 2;

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_D07D, String::from("ext4"));
    (m, sb)
}

/// The `..` entry inode is at byte 12 of a directory's first block (Linux ext4
/// layout: `.` [0..12] then `..` [12..]).
fn dotdot_of(m: &Arc<ext4::rootfs::Ext4Mount>, ino: u32) -> u32 {
    let node = m.state().mount.read_inode(ino).unwrap();
    let blk = m.state().mount.read_file_block(&node, 0).unwrap();
    u32::from_le_bytes([blk[12], blk[13], blk[14], blk[15]])
}
fn nlink(m: &Arc<ext4::rootfs::Ext4Mount>, ino: u32) -> u16 {
    m.state().mount.read_inode(ino).unwrap().links_count
}

#[test]
fn cross_parent_dir_rename_fixes_dotdot_and_nlinks() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let a = m.state().mount.create_dir(ROOT, b"a", 0o755, 0, 0).expect("mkdir a");
    let b = m.state().mount.create_dir(ROOT, b"b", 0o755, 0, 0).expect("mkdir b");
    let sub = m.state().mount.create_dir(a, b"sub", 0o755, 0, 0).expect("mkdir a/sub");

    assert_eq!(dotdot_of(&m, sub), a, "sub/.. starts at a");
    let (a_nl0, b_nl0) = (nlink(&m, a), nlink(&m, b));

    m.state().rename_at(b"/a/sub", b"/b/sub").expect("rename a/sub -> b/sub");

    assert_eq!(dotdot_of(&m, sub), b, "sub/.. now points at new parent b");
    assert_eq!(nlink(&m, a), a_nl0 - 1, "old parent a lost the .. back-ref");
    assert_eq!(nlink(&m, b), b_nl0 + 1, "new parent b gained the .. back-ref");
    assert!(m.state().mount.lookup_path(b"/b/sub").is_ok(), "b/sub present");
    assert!(m.state().mount.lookup_path(b"/a/sub").is_err(), "a/sub gone");

    // Persist across remount.
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    assert_eq!(dotdot_of(&m2, sub), b, "remount: sub/.. persisted");
    assert_eq!(nlink(&m2, a), a_nl0 - 1, "remount: a nlink persisted");
    assert_eq!(nlink(&m2, b), b_nl0 + 1, "remount: b nlink persisted");
}
