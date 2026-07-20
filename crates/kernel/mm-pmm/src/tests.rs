// Hosted tests + proptest oracle per `10§9`. Comprehensive coverage:
// boundaries, overflow, alignment, overlap, fragmentation, error
// paths, multi-region, bitmap-word edges, concurrent contention.

mod alloc_free;
mod accounting;
mod concurrent;
mod init;
mod reserve;

use super::*;
use core::sync::atomic::AtomicU64;
use proptest::prelude::*;
use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
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
    bitmaps: [&'static [AtomicU64]; ORDERS],
}

// SAFETY: backing buffer is leaked for the test process lifetime; only
// the owning Pmm dereferences via page_ptr, serialized by Spinlock.
unsafe impl Send for HostedBacking {}
// SAFETY: see Send impl above.
unsafe impl Sync for HostedBacking {}

impl HostedBacking {
    fn new(n_pages: u64) -> Self {
        let buf = vec![0u8; (n_pages.max(1) as usize) * PAGE].into_boxed_slice();
        let pages = Box::leak(buf).as_mut_ptr();
        let mut bitmaps = [&[][..]; ORDERS];
        for o in 0..ORDERS {
            let blocks = (n_pages + (1u64 << o) - 1) >> o;
            let words = ((blocks + 63) >> 6) as usize;
            let v: Vec<AtomicU64> = (0..words.max(1)).map(|_| AtomicU64::new(0)).collect();
            bitmaps[o] = Box::leak(v.into_boxed_slice());
        }
        Self {
            pages,
            n_pages,
            bitmaps,
        }
    }
}

impl PageBacking for HostedBacking {
    unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8 {
        debug_assert!(pfn.0 < self.n_pages);
        // SAFETY: pfn < n_pages per debug_assert; offset stays inside leaked buf.
        unsafe { self.pages.add((pfn.0 as usize) * PAGE) }
    }

    fn bitmap_storage(&self, order: u8, len_u64: usize) -> &'static [AtomicU64] {
        let s = self.bitmaps[order as usize];
        assert!(
            s.len() >= len_u64,
            "bitmap too small for order {}: have {} need {}",
            order,
            s.len(),
            len_u64
        );
        s
    }
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
