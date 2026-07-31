//! C5(crtime) integration: `i_crtime` decode → Inode.crtime (drives statx
//! STATX_BTIME). A freshly created file carries a crtime (stamped by A1); a
//! hand-written i_crtime round-trips through the decoder.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const MINI: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

// A fixed, non-zero wall clock for the create-time stamp (hosted has no kernel
// clock; tests install a provider like mtime_on_write_image does).
const T_CREATE: u64 = 1_700_000_000_000_000_000; // 2023-11-14 in ns
fn clock() -> u64 { T_CREATE }
fn t_create() -> vfs::Timespec64 { vfs::Timespec64::from_clock_ns(T_CREATE) }

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (MINI.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: MINI.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn created_file_has_crtime() {
    vfs::inode_times::set_realtime_provider(clock);
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"born.bin", 0o644, 0, 0).unwrap();
    let i = m.read_inode(n).unwrap();
    // create stamps crtime = ctime = mtime = current_time (ext4_new_inode).
    assert_eq!(i.crtime, Some(t_create()), "created file's birth time = create clock");
    assert_eq!(i.crtime, Some(i.ctime), "crtime equals ctime at create");
}

#[test]
fn crtime_survives_remount() {
    vfs::inode_times::set_realtime_provider(clock);
    let disk = build_disk();
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let n = m.create_file(2, b"persist.bin", 0o644, 0, 0).unwrap();
        assert_eq!(m.read_inode(n).unwrap().crtime, Some(t_create()));
    }
    let m2 = ext4::Mount::open(disk).unwrap();
    let n = m2.lookup_path(b"/persist.bin").unwrap();
    assert_eq!(m2.read_inode(n).unwrap().crtime, Some(t_create()), "crtime persists across remount");
}

#[test]
fn hand_written_crtime_decodes() {
    // Write a known i_crtime (secs @0x90) + i_crtime_extra (nsec<<2 @0x94) into
    // an inode slot and confirm the decoder reconstructs the absolute-ns value.
    const OFF_CRTIME: usize = 0x90;
    const OFF_CRTIME_EXTRA: usize = 0x94;
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"ht.bin", 0o644, 0, 0).unwrap();

    let (mut bytes, _) = m.read_inode_bytes(n).unwrap();
    let secs: u32 = 1_700_000_000;         // 2023-11-14
    let nsec: u32 = 123_456_789;
    bytes[OFF_CRTIME..OFF_CRTIME + 4].copy_from_slice(&secs.to_le_bytes());
    // extra: epoch_hi (bits[1:0]) = 0, nanoseconds in bits[31:2].
    bytes[OFF_CRTIME_EXTRA..OFF_CRTIME_EXTRA + 4].copy_from_slice(&(nsec << 2).to_le_bytes());
    m.write_inode_bytes(n, &bytes).unwrap();

    let i = m.read_inode(n).unwrap();
    assert_eq!(i.crtime, Some(vfs::Timespec64::new(secs as i64, nsec)),
        "i_crtime + extra decode to the (sec, nsec) pair");
}
