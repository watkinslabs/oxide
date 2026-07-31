//! A2 (ext4fix §2.2): a rw ext4 mount marks the on-disk superblock
//! not-cleanly-unmounted (clears `EXT4_VALID_FS`) + bumps `s_mnt_count` +
//! records `s_mtime`; a clean unmount (Ext4Mount drop) restores `EXT4_VALID_FS`.
//!
//! Without this the superblock state never reflects an oxide session, so a
//! real-Linux `e2fsck` / `mount` cannot tell a crashed fs from a clean one
//! (the fsck-interop half of the "uncleanly shut down" divergence).
//!
//! Image: mini-j.img (journaled — the SB writeback runs through run_journaled).

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

// ext4 superblock: byte offset of the fields under test (from the 1024-byte SB
// which itself sits at byte 1024 on-disk).
const SB_BYTE: usize = 1024;
const OFF_MNT_COUNT: usize = 0x34;
const OFF_STATE: usize = 0x3A;
const EXT4_VALID_FS: u16 = 0x0001;

static NOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
fn now_provider() -> u64 { NOW.load(core::sync::atomic::Ordering::Relaxed) }
const T_MOUNT: u64 = 1_720_000_000 * 1_000_000_000;

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

/// Read `(s_state, s_mnt_count)` straight off the backing device.
fn read_sb(disk: &Arc<dyn BlockDevice>) -> (u16, u16) {
    let mut req = BlockRequest {
        op: BlockOp::Read, start_block: 0, len_blocks: 4, buffer: alloc::vec![0u8; 2048], ..Default::default() };
    disk.submit_sync(&mut req).expect("read sb");
    let b = &req.buffer;
    let state = u16::from_le_bytes([b[SB_BYTE + OFF_STATE], b[SB_BYTE + OFF_STATE + 1]]);
    let mnt = u16::from_le_bytes([b[SB_BYTE + OFF_MNT_COUNT], b[SB_BYTE + OFF_MNT_COUNT + 1]]);
    (state, mnt)
}

#[test]
fn mount_marks_dirty_unmount_marks_clean() {
    vfs::inode_times::set_realtime_provider(now_provider);
    NOW.store(T_MOUNT, core::sync::atomic::Ordering::Relaxed);

    let disk = shared_disk();
    let (state0, mnt0) = read_sb(&disk);
    assert_eq!(state0 & EXT4_VALID_FS, EXT4_VALID_FS, "image starts cleanly unmounted");

    // Mount rw: VALID_FS clears, mount count bumps.
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("mount");
    let (state1, mnt1) = read_sb(&disk);
    assert_eq!(state1 & EXT4_VALID_FS, 0, "rw mount clears VALID_FS (not-clean)");
    assert_eq!(mnt1, mnt0.wrapping_add(1), "mount count bumped");

    // Clean unmount (drop): VALID_FS restored.
    drop(m);
    let (state2, mnt2) = read_sb(&disk);
    assert_eq!(state2 & EXT4_VALID_FS, EXT4_VALID_FS, "clean unmount restores VALID_FS");
    assert_eq!(mnt2, mnt1, "unmount does not bump the mount count");
}
