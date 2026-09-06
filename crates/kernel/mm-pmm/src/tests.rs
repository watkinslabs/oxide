// Hosted tests + proptest oracle per `10§9`. Comprehensive coverage:
// boundaries, overflow, alignment, overlap, fragmentation, error
// paths, multi-region, bitmap-word edges, concurrent contention.

mod alloc_free;
mod accounting;
mod concurrent;
mod dma_bound;
mod hibernate;
mod init;
mod migratetype;
mod pcp;
mod reserve;
mod watermark_gate;
mod render_perf;

use super::*;
use core::sync::atomic::AtomicU64;
use proptest::prelude::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::vec;
use std::vec::Vec;

const PAGE: usize = PAGE_SIZE_BYTES as usize;

// ---------------------------------------------------------------------------
// Hosted page + bitmap backing.
// ---------------------------------------------------------------------------

struct HostedBacking {
    pages: *mut u8,
    n_pages: u64,
    bitmaps: [&'static [AtomicU64]; BITMAP_SLOTS],
    pcp: &'static PcpStorage,
}

// SAFETY: backing buffer is leaked for the test process lifetime; only
// the owning Pmm dereferences via page_ptr, serialized by Spinlock.
unsafe impl Send for HostedBacking {}
// SAFETY: see Send impl above.
unsafe impl Sync for HostedBacking {}

impl HostedBacking {
    fn new(n_pages: u64) -> Self {
        Self::filled(n_pages, 0)
    }

    fn filled(n_pages: u64, fill: u8) -> Self {
        let buf = vec![fill; (n_pages.max(1) as usize) * PAGE].into_boxed_slice();
        let pages = Box::leak(buf).as_mut_ptr();
        let mut bitmaps = [&[][..]; BITMAP_SLOTS];
        for o in 0..BITMAP_SLOTS {
            let words = if o == PAGEBLOCK_TYPE_SLOT {
                let pageblocks = n_pages.saturating_add(crate::zone::PAGEBLOCK_PAGES - 1) / crate::zone::PAGEBLOCK_PAGES;
                (pageblocks.saturating_add(31) / 32) as usize
            } else {
                let blocks = if o == PCP_BITMAP_SLOT || o == HIBERNATE_FORBIDDEN_SLOT { n_pages }
                    else { (n_pages + (1u64 << o) - 1) >> o };
                ((blocks + 63) >> 6) as usize
            };
            let v: Vec<AtomicU64> = (0..words.max(1)).map(|_| AtomicU64::new(0)).collect();
            bitmaps[o] = Box::leak(v.into_boxed_slice());
        }
        Self {
            pages,
            n_pages,
            bitmaps,
            pcp: Box::leak(Box::new(PcpStorage::new())),
        }
    }
}

impl PageBacking for HostedBacking {
    unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8 {
        debug_assert!(pfn.0 < self.n_pages);
        // SAFETY: pfn < n_pages per debug_assert; offset stays inside leaked buf.
        unsafe { self.pages.add((pfn.0 as usize) * PAGE) }
    }

    fn bitmap_storage(&self, slot: u8, len_u64: usize) -> &'static [AtomicU64] {
        let s = self.bitmaps[slot as usize];
        assert!(
            s.len() >= len_u64,
            "bitmap too small for order {}: have {} need {}",
            slot,
            s.len(),
            len_u64
        );
        s
    }

    fn pcp_storage(&self) -> &'static PcpStorage { self.pcp }
}

// The HugeTLB pool's hosted tests use this same buddy implementation rather
// than a second allocator model. The live kernel still reaches the HHDM-backed
// PMM through `setup::pmm_static`; this test-only instance supplies the
// identical `Pmm::alloc/free` contract without requiring a boot handoff.
static HUGE_TEST_PMM: OnceLock<Pmm<HostedBacking>> = OnceLock::new();
static HUGE_TEST_ALLOCS: OnceLock<Mutex<BTreeSet<(u64, u8)>>> = OnceLock::new();

pub(crate) fn test_alloc_contig(order: crate::Order, nowait: bool) -> Option<u64> {
    // The hosted backing is intentionally bounded: the HugeTLB coverage lane
    // exercises the default 2 MiB hstate, while unsupported gigantic requests
    // retain their real ENOMEM behavior instead of allocating a 1 GiB buffer.
    if order.0 > 9 { return None; }
    let p = HUGE_TEST_PMM.get_or_init(|| build(8192));
    let pfn = if nowait { p.alloc_gfp_nowait(order, 0).ok()? } else { p.alloc(order).ok()? };
    let pa = pfn.0 * PAGE_SIZE_BYTES;
    HUGE_TEST_ALLOCS
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .unwrap()
        .insert((pa, order.0));
    Some(pa)
}

pub(crate) unsafe fn test_free_contig(pa: u64, order: crate::Order) -> bool {
    let Some(p) = HUGE_TEST_PMM.get() else { return false; };
    let Some(allocs) = HUGE_TEST_ALLOCS.get() else { return false; };
    if !allocs.lock().unwrap().remove(&(pa, order.0)) { return false; }
    // SAFETY: the allocation ledger proves this is exactly a run returned by
    // `test_alloc_contig`, with the same order and physical alignment.
    unsafe { p.free(Pfn(pa / PAGE_SIZE_BYTES), order); }
    true
}

fn build(n_pages: u64) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(n_pages);
    Pmm::<HostedBacking>::init(
        b,
        &[UsableRegion {
            start: Pfn(0),
            len_pfn: n_pages,
        }],
    )
    .unwrap()
}

fn build_regions(total_pages: u64, regions: &[UsableRegion]) -> Pmm<HostedBacking> {
    let b = HostedBacking::new(total_pages);
    Pmm::<HostedBacking>::init(b, regions).unwrap()
}
