//! D5: chmod / chown / utimes persist to the ext4 on-disk inode.
//!
//! The VFS `notify_change` funnels chmod/chown/utimes through `i_op->setattr`;
//! ext4 overrides it (`ext4_setattr`) to journal the mutated inode. Faithfulness
//! is proven across a REMOUNT (a fresh `Ext4Mount` over the same backing
//! `MemDisk`): only a committed on-disk change survives the original mount being
//! dropped. Before D5 the change lived only in the in-core atomics and was lost
//! on inode eviction / reboot.
//!
//! Image: mini-j.img — a real journaled mkfs.ext4 image, so `run_journaled`
//! drives the commit/log path the durability relies on. 256-byte inodes, so the
//! nanosecond / epoch-high `i_*time_extra` fields round-trip too.

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::idmap::Idmap;
use vfs::SuperBlock;

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

/// Mount `disk` and back-stamp a live `SuperBlock` (populates the per-SB icache
/// the in-memory nlink authority relies on).
fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_00D5, String::from("ext4"));
    (m, sb)
}

// uid/gid deliberately exceed 16 bits so the osd2 high halves (@0x78/@0x7A) are
// exercised — the low-only `stamp_owner` would drop them.
const D5_UID: u32 = 123_456;
const D5_GID: u32 = 654_321;
const D5_MODE: u16 = 0o2750;
// Sub-second ns so the `i_*time_extra` (nsec<<2 | epoch) path round-trips.
const D5_ATIME: u64 = 1_600_000_000 * 1_000_000_000 + 123_456_789;
const D5_MTIME: u64 = 1_700_000_000 * 1_000_000_000 + 987_654_321;
const D5_CTIME: u64 = 1_650_000_000 * 1_000_000_000 + 555_000_111;
fn ts(ns: u64) -> vfs::Timespec64 { vfs::Timespec64::from_clock_ns(ns) }

#[test]
fn chmod_chown_utimes_survive_remount() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let st = m.state();
    let inode = st.create_at(b"/d5.txt", 0o644).expect("create d5.txt");

    // One setattr carrying mode + owner + both timestamps, exactly as the VFS
    // notify_change builds after setattr_prepare.
    let ia = vfs::Iattr {
        valid: vfs::ATTR_MODE | vfs::ATTR_UID | vfs::ATTR_GID | vfs::ATTR_ATIME | vfs::ATTR_MTIME,
        mode: D5_MODE, uid: D5_UID, gid: D5_GID,
        atime: ts(D5_ATIME), mtime: ts(D5_MTIME), ctime: ts(D5_CTIME), size: 0,
    };
    inode.setattr(&Idmap::identity(), &ia).expect("ext4 setattr");

    // In-core is coherent immediately.
    assert_eq!(inode.perm(), Some(D5_MODE & 0o7777), "in-core mode after setattr");
    assert_eq!(inode.uid(), Some(D5_UID), "in-core uid");
    assert_eq!(inode.gid(), Some(D5_GID), "in-core gid");

    // Drop the mount, REMOUNT the same disk: the committed metadata survives.
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let node = m2.state().lookup_inode_any(b"/d5.txt").expect("lookup d5.txt after remount");

    assert_eq!(node.perm(), Some(D5_MODE & 0o7777), "remount: chmod persisted (incl. setgid)");
    assert_eq!(node.uid(), Some(D5_UID), "remount: chown uid persisted (>16-bit high half)");
    assert_eq!(node.gid(), Some(D5_GID), "remount: chown gid persisted (>16-bit high half)");
    assert_eq!(node.atime(), Some(ts(D5_ATIME)), "remount: utimes atime persisted (ns)");
    assert_eq!(node.mtime(), Some(ts(D5_MTIME)), "remount: utimes mtime persisted (ns)");
    assert_eq!(node.ctime(), Some(ts(D5_CTIME)), "remount: ctime persisted (ns)");
}

#[test]
fn size_setattr_persists_size_and_times_in_one_inode_write() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let st = m.state();
    let inode = st.create_at(b"/truncate-d5.txt", 0o644).expect("create truncate-d5.txt");
    let ino = inode.ino() as u32;
    let bs = st.mount.sb.block_size as u64;
    st.mount.write_at(ino, 0, &vec![0x41; (bs * 3) as usize]).expect("seed truncate file");
    let before = st.mount.read_inode(ino).expect("raw before size setattr");
    assert_eq!(before.size, bs * 3);

    let new_mtime = 1_710_000_000 * 1_000_000_000 + 222_333_444;
    let new_ctime = 1_710_000_001 * 1_000_000_000 + 333_444_555;
    let ia = vfs::Iattr {
        valid: vfs::ATTR_SIZE | vfs::ATTR_MTIME | vfs::ATTR_CTIME,
        size: bs,
        mtime: ts(new_mtime),
        ctime: ts(new_ctime),
        ..Default::default()
    };
    st.mount.fail_inode_write_after_for_tests(1);
    inode.setattr(&Idmap::identity(), &ia).expect("size setattr must not fail after truncate");

    let after = st.mount.read_inode(ino).expect("raw after size setattr");
    assert_eq!(after.size, bs, "raw inode size changed by combined truncate");
    assert!(after.i_blocks < before.i_blocks, "truncate released blocks");
    drop(sb); drop(m);

    let (m2, _sb2) = mount(disk);
    let node = m2.state().lookup_inode_any(b"/truncate-d5.txt").expect("lookup truncate-d5 after remount");
    assert_eq!(node.size(), bs, "remount: size persisted");
    assert_eq!(node.mtime(), Some(ts(new_mtime)), "remount: mtime persisted with size");
    assert_eq!(node.ctime(), Some(ts(new_ctime)), "remount: ctime persisted with size");
}
