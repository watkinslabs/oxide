//! Cross-operation journal-commit cost. Creating N files issues N independent
//! journal commits today (each `create_file` = one `run_journaled` scope =
//! commit_metadata + 3 dev.flush()). This is the systematic sysinit slowness
//! (tmpfiles, hwdb, …): every metadata op commits+flushes separately, vs Linux
//! jbd2 batching many ops into one running transaction. Measures block-write
//! ops over N create_file calls on the journaled image via StatsDev, and shows
//! an explicit batch (one run_journaled around all N) collapses to ~1 commit.

extern crate alloc;
mod common;

use alloc::sync::Arc;

use block::stats::StatsDev;
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
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

/// Baseline: N independent create_file calls. Each is its own committed
/// transaction — write-ops scale with N.
#[test]
fn per_op_create_scales_with_count() {
    common::boot_hosted_pmm();
    let base: Arc<dyn BlockDevice> = fresh_disk();
    let (dev, stats) = StatsDev::wrap(base);
    let m = ext4::Mount::open(dev).unwrap();
    let root = m.lookup_path(b"/").expect("root");

    const N: usize = 20;
    let (_, _, w0, _, _) = stats.snapshot();
    for i in 0..N {
        let mut name = alloc::vec![b'f'];
        name.extend_from_slice(alloc::format!("{i:03}").as_bytes());
        m.create_file(root, &name, 0o644, 0, 0).expect("create");
    }
    let (_, _, w1, _, _) = stats.snapshot();
    let per_op = (w1 - w0) as f64 / N as f64;
    eprintln!("per-op create: {} write-ops for {} files ({:.1}/file)", w1 - w0, N, per_op);
    assert!(per_op > 4.0, "each create should be its own commit (sanity)");
}

/// Batched: the SAME N creates wrapped in one `run_journaled` commit once.
/// Write-ops should be far below N× the per-op cost — this is what cross-op
/// batching buys the boot path.
#[test]
fn batched_create_commits_once() {
    common::boot_hosted_pmm();
    let base: Arc<dyn BlockDevice> = fresh_disk();
    let (dev, stats) = StatsDev::wrap(base);
    let m = ext4::Mount::open(dev).unwrap();
    let root = m.lookup_path(b"/").expect("root");

    const N: usize = 20;
    // Per-op reference on a separate disk.
    let ref_disk: Arc<dyn BlockDevice> = fresh_disk();
    let (ref_dev, ref_stats) = StatsDev::wrap(ref_disk);
    let rm = ext4::Mount::open(ref_dev).unwrap();
    let rroot = rm.lookup_path(b"/").unwrap();
    let (_, _, rw0, _, _) = ref_stats.snapshot();
    for i in 0..N {
        let mut name = alloc::vec![b'r'];
        name.extend_from_slice(alloc::format!("{i:03}").as_bytes());
        rm.create_file(rroot, &name, 0o644, 0, 0).expect("ref create");
    }
    let (_, _, rw1, _, _) = ref_stats.snapshot();
    let per_op_total = rw1 - rw0;

    // Batched on the main disk.
    let (_, _, w0, _, _) = stats.snapshot();
    m.run_journaled(|mm| {
        for i in 0..N {
            let mut name = alloc::vec![b'f'];
            name.extend_from_slice(alloc::format!("{i:03}").as_bytes());
            mm.create_file(root, &name, 0o644, 0, 0)?;
        }
        Ok(())
    }).expect("batched creates");
    let (_, _, w1, _, _) = stats.snapshot();
    let batched = w1 - w0;
    eprintln!("N={N}: per-op={per_op_total} write-ops, batched={batched} write-ops");
    assert!(batched * 2 < per_op_total,
        "batching N creates into one txn must cut write-ops well below per-op ({batched} vs {per_op_total})");

    // Integrity: all batched files visible after remount.
    drop(m);
    // (StatsDev holds the disk; a remount would need the same Arc — covered by
    //  the create_file_inside_scope_atomically test in journal_image. Here we
    //  only assert the commit-count reduction.)
    let _ = per_op_total;
}
