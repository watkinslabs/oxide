//! `cachestat(2)`'s page-cache walk over a REAL shmem address_space
//! (`filemap_cachestat` over `mapping->i_pages`). The counters have to follow
//! the frames actually committed by writes and released by truncation, which
//! only a live PMM-backed tmpfs inode can show.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use std::sync::OnceLock;

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use fs::tmpfs::TmpfsFs;
use vfs::{CachestatCounts, CachestatRange, CreateCtx, InodeRef};

const PAGE_SHIFT: u32 = 12;
const PG: u64 = 1 << PAGE_SHIFT;
const FILE_MODE: u32 = 0o644;

static PMM: OnceLock<()> = OnceLock::new();
const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;

/// shmem commits REAL frames, so the walk needs a live PMM to observe.
fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).expect("pool layout");
        // SAFETY: non-zero, page-aligned host allocation leaked for the test-binary lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1, memmap_ptr: regions.as_ptr(), seed: [0u8; 32], boot_ns: 0,
            rsdp_pa: 0, hhdm_offset: buf, smp_info_array: 0, smp_count: 0, bsp_lapic_id: 0, _pad: 0,
        };
        // SAFETY: BootInfo names a live region slice for this call; HHDM maps to leaked host memory.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((HOSTED_PMM_POOL as u64) / 4096);
    });
}

struct Fixture { _fs: Arc<TmpfsFs>, ino: InodeRef }

fn fixture(name: &str) -> Fixture {
    boot_hosted_pmm();
    let fs = TmpfsFs::new(String::from("cachestat-tmpfs"));
    let ino = fs.root_inode().create_child(name, FILE_MODE, &CreateCtx::root()).expect("create");
    Fixture { _fs: fs, ino }
}

fn write(f: &Fixture, off: u64, len: usize) {
    let buf = alloc::vec![0xA5u8; len];
    assert_eq!(f.ino.write(off, &buf), Ok(len));
}

fn stat(f: &Fixture, off: u64, len: u64) -> CachestatCounts {
    f.ino.i_mapping().expect("tmpfs inode has an address_space")
        .cachestat(CachestatRange::from_bytes(off, len, PAGE_SHIFT))
}

// A file with no data committed has an empty index space: every counter zero,
// including over a `len == 0` whole-file request.
#[test]
fn empty_file_reports_all_zero() {
    let f = fixture("empty");
    assert_eq!(stat(&f, 0, 0), CachestatCounts::default());
}

// `nr_cache` follows the frames a write actually commits, and a whole-file
// (`len == 0`) request sees all of them.
#[test]
fn written_pages_are_counted_as_cache() {
    let f = fixture("written");
    write(&f, 0, (4 * PG) as usize);
    let cs = stat(&f, 0, 0);
    assert_eq!(cs.nr_cache, 4);
    // shmem has no backing store to write back to, so it never tags the
    // mapping dirty and never has writeback in flight.
    assert_eq!(cs.nr_dirty, 0);
    assert_eq!(cs.nr_writeback, 0);
    // Nothing was evicted, so there are no shadows.
    assert_eq!(cs.nr_evicted, 0);
    assert_eq!(cs.nr_recently_evicted, 0);
}

// The byte range selects pages, not bytes: a sub-page request counts the whole
// page it lands in, and a request ending on a page boundary excludes the next.
#[test]
fn byte_range_selects_the_pages_it_touches() {
    let f = fixture("range");
    write(&f, 0, (4 * PG) as usize);
    assert_eq!(stat(&f, 0, 1).nr_cache, 1);
    assert_eq!(stat(&f, 0, PG).nr_cache, 1);
    assert_eq!(stat(&f, 0, PG + 1).nr_cache, 2);
    assert_eq!(stat(&f, PG, 2 * PG).nr_cache, 2);
    assert_eq!(stat(&f, 3 * PG, 0).nr_cache, 1);
    // Entirely past the committed pages: nothing to count, no error.
    assert_eq!(stat(&f, 64 * PG, 0).nr_cache, 0);
}

// A sparse file's holes are absent indices, not zero pages: only the committed
// page counts even though the whole-file range spans the hole.
#[test]
fn holes_are_absent_indices_not_cache_pages() {
    let f = fixture("sparse");
    write(&f, 100 * PG, PG as usize);
    assert_eq!(stat(&f, 0, 0).nr_cache, 1);
    assert_eq!(stat(&f, 0, 100 * PG).nr_cache, 0);
    assert_eq!(stat(&f, 100 * PG, PG).nr_cache, 1);
}

// Truncation removes the indices outright — no page, and no shadow either,
// because the pages did not leave under memory pressure.
#[test]
fn truncate_drops_indices_without_leaving_shadows() {
    let f = fixture("truncate");
    write(&f, 0, (4 * PG) as usize);
    assert_eq!(stat(&f, 0, 0).nr_cache, 4);
    f.ino.truncate(PG).expect("truncate");
    let cs = stat(&f, 0, 0);
    assert_eq!(cs.nr_cache, 1);
    assert_eq!(cs.nr_evicted, 0);
}

// An inverted range (one whose byte end wrapped past `u64::MAX`) contains no
// index, so the walk reports zeros rather than scanning the whole file.
#[test]
fn wrapped_range_counts_nothing() {
    let f = fixture("wrapped");
    write(&f, 0, (4 * PG) as usize);
    let cs = stat(&f, u64::MAX - PG, 4 * PG);
    assert_eq!(cs, CachestatCounts::default());
}
