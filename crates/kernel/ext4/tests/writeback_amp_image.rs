//! Writeback amplification: a large buffered file flushed via the framecache
//! must NOT issue O(pages) synchronous journal commits (one per page) — that is
//! the systemd-hwdb-update sysinit stall (~1358 commits for 13.5MB @ ~87/s).
//! Measures block-device WRITE ops across `writeback()` via a StatsDev.
//! See memory `hwdb-blocker-ext4-writeback-commits`.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::stats::StatsDev;
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const PG: usize = 4096;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn large_file_writeback_is_not_per_page_commit() {
    common::boot_hosted_pmm();
    let base: Arc<dyn BlockDevice> = fresh_disk();
    let (dev, stats) = StatsDev::wrap(base);

    let m = ext4::rootfs::Ext4Mount::open(dev).unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let root_ino_arc = fs.root();
    let _sb = SuperBlock::for_backend(fs.clone(), root_ino_arc, 0x1234_5678, String::from("ext4"));
    let st = m.state();

    // A file big enough that per-page commits would dominate (128 pages = 512KB).
    const NPAGES: usize = 40;
    let total = NPAGES * PG;
    let mut pat = alloc::vec![0u8; total];
    for (i, b) in pat.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2654435761).to_le_bytes()[0];
    }

    let root = st.lookup_path(b"/").expect("root");
    let ino = st.mount.create_file(root, b"big.dat", 0o644, 0, 0).expect("create");
    let f = st.wrap_file(ino).expect("wrap");

    // Buffered writes (no disk I/O yet), then a single writeback.
    let mut off = 0usize;
    for chunk in [PG, PG * 7 + 100, total - PG - (PG * 7 + 100)] {
        f.write(off as u64, &pat[off..off + chunk]).expect("write");
        off += chunk;
    }

    let (_, _, w_before, _, _) = stats.snapshot();
    f.i_mapping().unwrap().writeback().expect("writeback");
    let (_, _, w_after, _, _) = stats.snapshot();

    let writes = w_after - w_before;
    eprintln!("writeback of {} pages: {} block-write ops ({:.2}/page)",
              NPAGES, writes, writes as f64 / NPAGES as f64);

    // Each per-page journal commit writes descriptor + data + commit + journal-SB
    // (twice) + the target metadata: ~20 write-ops/page on this journaled image
    // (measured baseline: 800 ops for 40 pages). Batching the whole writeback
    // into ONE transaction commits once: ~8 ops/page (measured 332). Assert well
    // under the per-page baseline — a regression to per-page commits (the sysinit
    // stall) trips this. Also guards the O(n²) re-extend: that BLOWS UP writes.
    assert!(writes < (NPAGES as u64) * 12,
        "writeback issued {} write-ops for {} pages — per-page journal-commit amplification \
         (batched ~8/page; per-page ~20/page; O(n²) re-extend far higher)",
        writes, NPAGES);
}
