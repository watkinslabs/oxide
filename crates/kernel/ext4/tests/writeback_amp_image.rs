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

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const PG: usize = 4096;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
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
    let _sb = common::realize_sb(fs.clone(), root_ino_arc, 0x1234_5678, String::from("ext4"));
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

    let (r_before, _, w_before, _, _) = stats.snapshot();
    f.i_mapping().unwrap().writeback().expect("writeback");
    let (r_after, _, w_after, _, _) = stats.snapshot();

    let writes = w_after - w_before;
    let reads = r_after - r_before;
    eprintln!("writeback of {} pages: {} block-write ops ({:.2}/page), {} block-read ops",
              NPAGES, writes, writes as f64 / NPAGES as f64, reads);

    // Full-block, block-aligned data writes must SKIP the read-modify-write
    // pre-read (the whole block is overwritten). Before the write_byte_range
    // fast path, every data block did a useless pre-read — 27k serialized
    // reads on hwdb's 13.5MB file, doubling its fsync I/O. A per-page pre-read
    // regression trips this (reads would be >= NPAGES).
    assert!(reads < NPAGES as u64,
        "writeback issued {} block-read ops for {} full-block pages — the RMW \
         pre-read for block-aligned full-block writes is dead I/O (should be ~0)",
        reads, NPAGES);

    // Journaled-image write-op history for this 40-page writeback:
    //   per-page commit (old):  ~20/page (800)
    //   one-txn batch (B679):   ~8/page  (332)
    //   RMW-read skip (B701):   ~4/page  (172)
    //   coalesced data writes:  ~1.3/page (52) — contiguous data blocks collapse
    //     into ~one 128KB device request instead of 32 4KB writes.
    // Assert < 2/page: catches a regression that loses coalescing (back to
    // per-block ~4/page) OR per-page journal commits (~20/page) OR the O(n²)
    // re-extend (far higher). The residual is the metadata journal commit.
    assert!(writes < (NPAGES as u64) * 2,
        "writeback issued {} write-ops for {} pages — lost data-write coalescing \
         (coalesced ~1.3/page; per-block ~4/page; per-page-commit ~20/page)",
        writes, NPAGES);

    // Correctness: the coalesced/deferred data writes must land the exact bytes.
    // Re-open the inode fresh (bypass any cached frame) and read the whole file
    // back through the mount, comparing to the pattern. A coalescing bug
    // (mis-ordered runs, wrong physical block, dropped tail) corrupts this.
    st.page_cache.invalidate(block::types::InodeId(ino as u64));
    let mut got = alloc::vec![0u8; total];
    let rf = st.wrap_file(ino).expect("re-wrap");
    let n = rf.read(0, &mut got).expect("readback");
    assert_eq!(n, total, "short readback: {} of {}", n, total);
    assert!(got == pat, "coalesced writeback corrupted file data");
}
