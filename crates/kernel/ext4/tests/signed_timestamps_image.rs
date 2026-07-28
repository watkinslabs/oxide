//! Signed ext4 timestamps end-to-end over a real image: the write path
//! (`persist_inode_meta` → `EXT4_INODE_SET_XTIME_VAL`) and the read path
//! (`Inode::parse` → `EXT4_INODE_GET_XTIME_VAL`) must round-trip the whole
//! `EXT4_TIMESTAMP_MIN..EXT4_EXTRA_TIMESTAMP_MAX` window — 1901-12-13 through
//! 2446-05-10 — not just the post-epoch part a `u64`-of-nanoseconds model
//! could express.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::Timespec64;

const MINI: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (MINI.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: MINI.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn pre_1970_and_far_future_times_survive_the_persist_path() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"signed.bin", 0o644, 0, 0).unwrap();
    let mode = m.read_inode(n).unwrap().mode;

    // 1906-08-16, 2446-05-10 (EXT4_EXTRA_TIMESTAMP_MAX), and the epoch itself.
    let past   = Timespec64::new(-2_000_000_000, 123_456_789);
    let future = Timespec64::new(ext4::EXT4_EXTRA_TIMESTAMP_MAX, 999_999_999);
    let epoch  = Timespec64::ZERO;
    m.persist_inode_meta(n, mode, 0, 0, past, future, epoch).unwrap();

    let i = m.read_inode(n).unwrap();
    assert_eq!(i.atime, past, "pre-1970 atime round-trips through the on-disk pair");
    assert_eq!(i.mtime, future, "the year-2446 cap round-trips (no ns-scalar overflow)");
    assert_eq!(i.ctime, epoch);
    // Signed ordering, which an unsigned-ns model inverts: 1906 < 1970 < 2446.
    assert!(i.atime < i.ctime, "1906 sorts BEFORE the epoch");
    assert!(i.ctime < i.mtime);
}

#[test]
fn the_earliest_representable_second_round_trips() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"min.bin", 0o644, 0, 0).unwrap();
    let mode = m.read_inode(n).unwrap().mode;

    // 1901-12-13 — `EXT4_TIMESTAMP_MIN`, the earliest ext4 can store.
    let min = Timespec64::from_secs(ext4::EXT4_TIMESTAMP_MIN);
    m.persist_inode_meta(n, mode, 0, 0, min, min, min).unwrap();

    let i = m.read_inode(n).unwrap();
    assert_eq!(i.mtime, min);
    assert_eq!(i.mtime.sec, i32::MIN as i64);
}

#[test]
fn a_hand_written_high_bit_base_with_zero_extra_reads_back_pre_epoch() {
    // An image written by any other ext4 implementation: `i_mtime` holds the
    // low 32 bits of a NEGATIVE second and `i_mtime_extra` is 0. The decoder
    // must sign-extend, not zero-extend.
    const OFF_MTIME: usize = 0x10;
    const OFF_MTIME_EXTRA: usize = 0x88;
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"legacy.bin", 0o644, 0, 0).unwrap();

    let (mut bytes, _) = m.read_inode_bytes(n).unwrap();
    let raw_base = (-2_000_000_000i32) as u32;
    assert!(raw_base & 0x8000_0000 != 0);
    bytes[OFF_MTIME..OFF_MTIME + 4].copy_from_slice(&raw_base.to_le_bytes());
    bytes[OFF_MTIME_EXTRA..OFF_MTIME_EXTRA + 4].copy_from_slice(&0u32.to_le_bytes());
    m.write_inode_bytes(n, &bytes).unwrap();

    let i = m.read_inode(n).unwrap();
    assert_eq!(i.mtime, Timespec64::from_secs(-2_000_000_000));
    assert_ne!(i.mtime.sec, raw_base as i64, "not the zero-extended year-2106 reading");
}
