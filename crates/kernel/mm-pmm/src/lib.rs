// Physical Memory Manager — buddy allocator with bitmap-as-truth.
// Per docs/10 (FROZEN). Linux-class buddy: bitmap[o] bit i ⇔ "block of
// order o at PFN i<<o is free". Free-list = derived index inside the
// freed pages themselves (intrusive doubly-linked LIFO per `10§5.2`).
//
// Sized dynamically: any pfn_max from a few MiB to multiple TiB. Bitmap
// storage allocated from a `PageBacking::bitmap_storage` callback so the
// boot-allocator owns the policy. No fixed-N region arrays; init takes
// `&[UsableRegion]`. Single zone for v1 per `10§1`.
//
// Invariants per `10§3` (held at every quiescent point):
//   I1 (bitmap-truth): bitmap[o].is_set(p) ⇔ "block of order o at p is free".
//   I2 (single-membership): a free order-o block sets exactly one bit in
//      bitmap[o]; bits at other orders covering the same memory are clear.
//   I3 (free-list ↔ bitmap): every block on free_list[o] has bit set;
//      every set bit is on free_list. Both directions.
//   I4 (buddy alignment): order-o block at p has p aligned to 1<<o.
//   I5 (no overlap).
//   I6 (total accounting): sum_o (count(bitmap[o]) << o)
//                          == initial_free - allocated.
//   I7 (poison-on-free): freed page first 16B == MAGIC u64 + order u8 + 7B 0.
//   I8 (MAX_ORDER bound): order > MAX_ORDER ⇒ Err(InvalidOrder).

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod buddy;
mod page_meta;
pub mod reclaim;
pub mod shrinker;
pub mod watermark;
#[cfg(target_os = "oxide-kernel")]
mod kswapd;
#[cfg(target_os = "oxide-kernel")]
mod memcg;

pub use buddy::{Pmm, PmmSnapshot};
pub use page_meta::{reclaim_state, PageFlags, PageMeta, PageMetaArr, ReclaimPageState};
#[cfg(target_os = "oxide-kernel")]
pub use kswapd::spawn_kswapd;
#[cfg(target_os = "oxide-kernel")]
pub use memcg::install_memcg_pressure_policy;

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
use hal::{Pfn, PAGE_SIZE_BYTES};
use sync::{Buddy, IrqGate, NoopIrq, Spinlock};

/// `MAX_ORDER` per `10§1`: 4 KiB (order 0) up to 4 GiB (order 20).
pub const MAX_ORDER: u8 = 20;

/// Number of bitmap+free-list slots, indexed `0..=MAX_ORDER`.
pub const ORDERS: usize = MAX_ORDER as usize + 1;

/// Free-page poison constant per `10§3` I7. Read at offset 0 of every
/// freed page; mismatch on alloc ⇒ kassert (corruption or double-free).
const POISON_MAGIC: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Sentinel for "no PFN" in free-list head/next/prev. A real PFN is
/// bounded by RAM-size in pages, always far below `u64::MAX`.
const PFN_NULL: u64 = u64::MAX;

/// Order = log2 of page count for a buddy block. `Pfn` aligned to `1<<order`.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Order(pub u8);

/// Subsystem error per `10§10` + `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidOrder,
    NoMem,
    OutOfRange,
    Corrupt,
    Overlap,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time region descriptor passed to [`Pmm::init`].
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UsableRegion {
    pub start: Pfn,
    pub len_pfn: u64,
}

// ---------------------------------------------------------------------------
// PageBacking — decouples Pfn↔raw-pointer + bitmap storage from buddy logic.
// ---------------------------------------------------------------------------

/// Physical-page + bitmap backing per `10§5`. Kernel impl reaches pages
/// via the direct-map and bitmaps via a boot-allocated region. Hosted
/// tests use a `Vec<u8>` shim. Generic-only; never `dyn` per `07§5`.
pub trait PageBacking: Send + Sync + 'static {
    /// Pointer to the first byte of PFN `pfn`.
    ///
    /// # SAFETY: caller guarantees `pfn` is in-range and PMM-owned for
    /// the operation. Returned pointer must be stable for kernel lifetime.
    unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8;

    /// Allocate/return zeroed bitmap storage for `words` u64s at `order`.
    /// The returned slice must have length `words` and be zero-filled.
    fn bitmap_storage(&self, order: u8, words: usize) -> &'static [AtomicU64];
}

// ---------------------------------------------------------------------------
// Local kassert! — bridges to `38` once that crate ships a real impl.
// ---------------------------------------------------------------------------

#[macro_export]
macro_rules! kassert {
    ($cond:expr, $msg:literal) => {{
        if !($cond) {
            panic!($msg);
        }
    }};
}

#[cfg(test)]
mod tests;

pub mod boot;
pub mod setup;
pub mod mmap_flags;
mod munmap_range;
pub mod swap;

pub use munmap_range::{validate_munmap_range, MunmapRange};

#[cfg(target_os = "oxide-kernel")]
pub mod user_as;
