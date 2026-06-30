//! ext4 D9 rename — ATOMIC `RENAME_EXCHANGE` + `RENAME_WHITEOUT`.
//!
//! Both ops run as a SINGLE journaled ext4 transaction (`run_journaled` →
//! `commit_metadata`), not the generic non-atomic temp-name / two-step dance.
//! Faithfulness is proven across a REMOUNT (a fresh `Ext4Mount` over the same
//! backing `MemDisk`): only a committed, self-consistent on-disk state can be
//! re-read after the original mount is dropped.
//!
//! Image: mini-j.img — a real journaled mkfs.ext4 image, so the commit drives
//! the journal log path (descriptor + data + commit + mark-clean) before the
//! target blocks land, exactly the durability ext4 RENAME_EXCHANGE/WHITEOUT
//! rely on.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{CreateCtx, FileType, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

/// One shared `MemDisk` so a second `Ext4Mount::open` over the SAME Arc sees
/// the committed bytes (a real remount, not a fresh fixture).
fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

/// Mount `disk` and back-stamp a live `SuperBlock` (so the per-SB icache the
/// in-memory nlink authority relies on is populated).
fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = SuperBlock::for_backend(fs, root, 0xE471_0002, String::from("ext4"));
    (m, sb)
}

#[test]
fn exchange_swaps_two_files_atomically_across_remount() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let root = sb.s_root_inode().expect("root inode");
    root.create_child("xa", 0o644, &CreateCtx::root()).expect("create xa");
    root.create_child("xb", 0o600, &CreateCtx::root()).expect("create xb");

    // Identity = on-disk inode number; the two differ.
    let a_ino = m.state().lookup_path(b"/xa").expect("xa ino");
    let b_ino = m.state().lookup_path(b"/xb").expect("xb ino");
    assert_ne!(a_ino, b_ino, "two distinct inodes");

    let fs: Arc<dyn FileSystem> = m.clone();
    fs.exchange("/xa", "/xb").expect("atomic exchange");

    // Same mount: names now resolve to each other's inode.
    assert_eq!(m.state().lookup_path(b"/xa"), Some(b_ino), "xa now holds b's inode");
    assert_eq!(m.state().lookup_path(b"/xb"), Some(a_ino), "xb now holds a's inode");

    // Drop the mount, REMOUNT the same disk: the committed swap survives.
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    assert_eq!(m2.state().lookup_path(b"/xa"), Some(b_ino), "remount: xa→b inode");
    assert_eq!(m2.state().lookup_path(b"/xb"), Some(a_ino), "remount: xb→a inode");
}

#[test]
fn whiteout_plants_chardev_at_source_dst_gets_moved_inode_across_remount() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let root = sb.s_root_inode().expect("root inode");
    root.create_child("wsrc", 0o644, &CreateCtx::root()).expect("create wsrc");
    let src_ino = m.state().lookup_path(b"/wsrc").expect("wsrc ino");

    let fs: Arc<dyn FileSystem> = m.clone();
    fs.whiteout("/wsrc", "/wdst").expect("atomic whiteout");

    // dst now holds the moved inode; src holds a fresh whiteout inode.
    assert_eq!(m.state().lookup_path(b"/wdst"), Some(src_ino), "wdst got the moved inode");
    let wo_ino = m.state().lookup_path(b"/wsrc").expect("whiteout present at source");
    assert_ne!(wo_ino, src_ino, "whiteout is a NEW inode, not the moved one");

    // Drop + REMOUNT: assert the moved inode + the whiteout chardev persisted.
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    assert_eq!(m2.state().lookup_path(b"/wdst"), Some(src_ino), "remount: wdst→moved inode");
    let wo_ino2 = m2.state().lookup_path(b"/wsrc").expect("remount: whiteout present");
    let wo = m2.state().wrap_any_ino(wo_ino2).expect("wrap whiteout inode");
    assert_eq!(wo.file_type(), FileType::CharDev, "whiteout is a char device");
    assert_eq!(wo.rdev(), 0, "whiteout rdev is 0:0");
}
