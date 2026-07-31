//! Cross-operation journal batching (Mount::begin_batch/commit_batch). With
//! batch mode on, metadata ops JOIN one running transaction (drained on trigger)
//! instead of committing per-op — the fix for the systematic sysinit slowness.
//! Verifies: (1) N creates auto-batch to ~1 commit and all persist, (2) a failed
//! op mid-batch rolls back WITHOUT touching prior batched ops (per-op atomicity).

extern crate alloc;
mod common;

use alloc::sync::Arc;

use block::stats::StatsDev;
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use ext4::MountError;
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

fn read_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32) -> alloc::vec::Vec<u8> {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest::new_read(fs_lba * sectors as u64, sectors, SECTOR);
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

/// N creates in batch mode commit far fewer block-writes than N per-op commits,
/// and every file persists after `commit_batch` + remount.
#[test]
fn batched_creates_defer_and_all_persist() {
    common::boot_hosted_pmm();
    let raw = fresh_disk();
    let base: Arc<dyn BlockDevice> = raw.clone();
    let (dev, stats) = StatsDev::wrap(base);
    let m = ext4::Mount::open(dev).unwrap();
    let root = m.lookup_path(b"/").expect("root");

    const N: usize = 20;
    m.begin_batch();
    let (_, _, w0, _, _) = stats.snapshot();
    for i in 0..N {
        let mut name = alloc::vec![b'b'];
        name.extend_from_slice(alloc::format!("{i:03}").as_bytes());
        m.create_file(root, &name, 0o644, 0, 0).expect("create");
    }
    let (_, _, w_mid, _, _) = stats.snapshot();
    m.commit_batch().expect("commit_batch");
    let (_, _, w1, _, _) = stats.snapshot();
    eprintln!("batch: {} write-ops during {} creates, {} at commit_batch",
              w_mid - w0, N, w1 - w_mid);
    // The creates themselves stage into the running txn — near-zero device
    // writes; the single commit_batch is the only heavy write burst.
    assert!(w_mid - w0 < (N as u64) * 3,
        "creates should defer, not commit per-op ({} writes for {N} creates)", w_mid - w0);

    drop(m);
    let m2 = ext4::Mount::open(raw as Arc<dyn BlockDevice>).unwrap();
    for i in 0..N {
        let mut name = alloc::vec![b'/', b'b'];
        name.extend_from_slice(alloc::format!("{i:03}").as_bytes());
        assert!(m2.lookup_path(&name).is_ok(), "batched file {i} persisted");
    }
}

/// A failing op mid-batch rolls back ONLY its own staged blocks; prior and
/// subsequent successful ops in the same running transaction are unaffected.
#[test]
fn failed_op_rolls_back_without_touching_prior() {
    common::boot_hosted_pmm();
    let raw = fresh_disk();
    let m = ext4::Mount::open(raw.clone() as Arc<dyn BlockDevice>).unwrap();
    let bs = m.sb.block_size as u64;
    // Non-critical scratch blocks (journal_image uses 100/120/130 the same way).
    let (a, b, c) = (140u64, 141u64, 142u64);
    let b_orig = read_fs_block(&(raw.clone() as Arc<dyn BlockDevice>), b, bs as u32);

    m.begin_batch();
    // A: succeeds -> stays in the running txn.
    m.run_journaled(|mm| mm.metadata_write(a * bs, &alloc::vec![0xAA; bs as usize])).unwrap();
    // B: stages then FAILS -> must be rolled back out of the shared shadow.
    let r = m.run_journaled(|mm| {
        mm.metadata_write(b * bs, &alloc::vec![0xBB; bs as usize])?;
        Err::<(), _>(MountError::NotFound)
    });
    assert!(r.is_err(), "op B deliberately failed");
    // C: succeeds -> stays.
    m.run_journaled(|mm| mm.metadata_write(c * bs, &alloc::vec![0xCC; bs as usize])).unwrap();
    m.commit_batch().unwrap();
    drop(m);

    let disk = raw as Arc<dyn BlockDevice>;
    assert_eq!(read_fs_block(&disk, a, bs as u32)[0], 0xAA, "A committed");
    assert_eq!(read_fs_block(&disk, c, bs as u32)[0], 0xCC, "C committed");
    assert_eq!(read_fs_block(&disk, b, bs as u32), b_orig,
        "B rolled back — its failed staging never reached disk, prior/next ops intact");
}
