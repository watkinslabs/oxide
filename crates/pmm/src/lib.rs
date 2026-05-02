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
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

use core::sync::atomic::{AtomicU64, Ordering};
use hal::{Pfn, PAGE_SIZE_BYTES};
use sync::{Buddy, NoopIrq, Spinlock};

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
    /// Out of memory at the requested order (or larger).
    NoMem,
    /// Order > `MAX_ORDER`.
    InvalidOrder,
    /// `init` empty regions, `free` pfn outside `[0, pfn_max)`,
    /// `reserve_early` past `pfn_max`, or a length+start overflow.
    OutOfRange,
    /// `init` regions overlap (caller invariant violated).
    Overlap,
    /// Subsystem not initialized.
    NotInit,
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
    /// Page-aligned pointer to the 4 KiB at `pfn`. Caller treats the
    /// page as kernel-owned (free-list node or about-to-zero allocation).
    ///
    /// # SAFETY: caller is the PMM holding the Buddy lock OR the boot
    /// path; the page is not concurrently aliased; `pfn` is valid.
    /// Returned pointer is page-aligned, points to `PAGE_SIZE_BYTES`.
    /// # C: O(1)
    unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8;

    /// Bitmap storage for `order`, ≥ `len_u64` words. Called once per
    /// order from [`Pmm::init`]. Lifetime: program's. Words start zeroed.
    /// # C: O(1)
    fn bitmap_storage(&self, order: u8, len_u64: usize) -> &'static [AtomicU64];
}

// ---------------------------------------------------------------------------
// FreeNode header r/w — page-content layout per `10§5.2`.
// ---------------------------------------------------------------------------
//
// Layout: 32 bytes at offset 0 of the freed page's first page.
//   poison: u64    @ 0
//   order:  u8     @ 8
//   _pad:  [u8;7]  @ 9..16
//   next:  u64     @ 16
//   prev:  u64     @ 24
//
// On secondary pages of an order-o block we only stamp the first 16
// bytes (poison + order). Alloc verifies poison on every page.

const OFF_POISON: usize = 0;
const OFF_ORDER: usize = 8;
const OFF_NEXT: usize = 16;
const OFF_PREV: usize = 24;

#[inline]
unsafe fn write_u64(base: *mut u8, off: usize, v: u64) {
    // SAFETY: `base + off` is in the 32-byte FreeNode header at the start
    // of a PMM-owned page; alignment-agnostic via write_unaligned.
    unsafe { core::ptr::write_unaligned(base.add(off) as *mut u64, v) }
}

#[inline]
unsafe fn read_u64(base: *const u8, off: usize) -> u64 {
    // SAFETY: `base + off` is in the 32-byte FreeNode header at the start
    // of a PMM-owned page; alignment-agnostic read.
    unsafe { core::ptr::read_unaligned(base.add(off) as *const u64) }
}

#[inline]
unsafe fn write_u8(base: *mut u8, off: usize, v: u8) {
    // SAFETY: `base + off` is inside a PMM-owned 4 KiB page at call site.
    unsafe { core::ptr::write(base.add(off), v) }
}

// ---------------------------------------------------------------------------
// PmmInner — protected by the Buddy spinlock.
// ---------------------------------------------------------------------------

struct PmmInner<B: PageBacking> {
    backing: B,
    pfn_max: u64,                                    // exclusive upper bound
    bitmaps: [&'static [AtomicU64]; ORDERS],
    free_heads: [u64; ORDERS],
    free_count: [u64; ORDERS],
    allocated: u64,
    initial_free: u64,
}

impl<B: PageBacking> PmmInner<B> {
    fn bitmap_get(&self, order: u8, idx: u64) -> bool {
        let word = (idx >> 6) as usize;
        let bit = (idx & 63) as u32;
        (self.bitmaps[order as usize][word].load(Ordering::Relaxed) >> bit) & 1 == 1
    }

    fn bitmap_set(&self, order: u8, idx: u64) {
        let word = (idx >> 6) as usize;
        let bit = (idx & 63) as u32;
        self.bitmaps[order as usize][word].fetch_or(1u64 << bit, Ordering::Relaxed);
    }

    fn bitmap_clear(&self, order: u8, idx: u64) {
        let word = (idx >> 6) as usize;
        let bit = (idx & 63) as u32;
        self.bitmaps[order as usize][word].fetch_and(!(1u64 << bit), Ordering::Relaxed);
    }

    /// Stamp poison + order on every page of the order-o block at `pfn`.
    /// On the head page only, also write next/prev.
    ///
    /// # SAFETY: block is order-aligned, in-range, currently NOT on any
    /// free-list; pages are PMM-owned at call site.
    unsafe fn stamp_block(&self, pfn: u64, order: u8, head_next: u64, head_prev: u64) {
        let span = 1u64 << order;
        for k in 0..span {
            // SAFETY: page within the order-o block; PMM-owned per fn contract.
            let p = unsafe { self.backing.page_ptr(Pfn(pfn + k)) };
            // SAFETY: write 16-byte header (poison+order) inside the page.
            unsafe {
                write_u64(p, OFF_POISON, POISON_MAGIC);
                write_u8(p, OFF_ORDER, order);
                for i in 1..8 { write_u8(p, OFF_ORDER + i, 0); }
            }
            if k == 0 {
                // SAFETY: write next/prev into the head page's header.
                unsafe {
                    write_u64(p, OFF_NEXT, head_next);
                    write_u64(p, OFF_PREV, head_prev);
                }
            }
        }
    }

    /// Push `pfn` to head of free_list[order]. Stamps FreeNode header.
    ///
    /// # SAFETY: `pfn` is order-aligned, in-range, currently NOT on any
    /// free-list; pages are PMM-owned at call site.
    unsafe fn push_free(&mut self, pfn: u64, order: u8) {
        let head = self.free_heads[order as usize];
        // SAFETY: pfn block PMM-owned per fn contract.
        unsafe { self.stamp_block(pfn, order, head, PFN_NULL) };
        if head != PFN_NULL {
            // SAFETY: old head's page is on the free-list ⇒ PMM-owned.
            let hp = unsafe { self.backing.page_ptr(Pfn(head)) };
            // SAFETY: write old head's prev field inside its header.
            unsafe { write_u64(hp, OFF_PREV, pfn) };
        }
        self.free_heads[order as usize] = pfn;
    }

    /// Pop head of free_list[order]. Caller updates bitmap + count.
    ///
    /// # SAFETY: free_list[order] is non-empty.
    unsafe fn pop_free(&mut self, order: u8) -> u64 {
        let head = self.free_heads[order as usize];
        debug_assert!(head != PFN_NULL);
        // SAFETY: head on free-list ⇒ PMM-owned page.
        let hp = unsafe { self.backing.page_ptr(Pfn(head)) };
        // SAFETY: header lives in first 32B of a PMM-owned page.
        let next = unsafe { read_u64(hp, OFF_NEXT) };
        if next != PFN_NULL {
            // SAFETY: `next` is on the free-list ⇒ PMM-owned page.
            let np = unsafe { self.backing.page_ptr(Pfn(next)) };
            // SAFETY: write into next-node's prev field; PMM-owned page.
            unsafe { write_u64(np, OFF_PREV, PFN_NULL) };
        }
        self.free_heads[order as usize] = next;
        head
    }

    /// Remove `pfn` from free_list[order] (used during merge / reserve).
    ///
    /// # SAFETY: `pfn` is currently on free_list[order]; page PMM-owned.
    unsafe fn unlink_free(&mut self, pfn: u64, order: u8) {
        // SAFETY: pfn on free-list ⇒ PMM-owned page.
        let p = unsafe { self.backing.page_ptr(Pfn(pfn)) };
        // SAFETY: header read inside owned page.
        let next = unsafe { read_u64(p, OFF_NEXT) };
        // SAFETY: header read inside owned page.
        let prev = unsafe { read_u64(p, OFF_PREV) };
        if prev == PFN_NULL {
            self.free_heads[order as usize] = next;
        } else {
            // SAFETY: prev on free-list ⇒ PMM-owned page.
            let pp = unsafe { self.backing.page_ptr(Pfn(prev)) };
            // SAFETY: writing prev's next field inside its header.
            unsafe { write_u64(pp, OFF_NEXT, next) };
        }
        if next != PFN_NULL {
            // SAFETY: next on free-list ⇒ PMM-owned page.
            let np = unsafe { self.backing.page_ptr(Pfn(next)) };
            // SAFETY: writing next's prev field inside its header.
            unsafe { write_u64(np, OFF_PREV, prev) };
        }
    }

    /// Verify poison on every page of the order-o block at `pfn`.
    ///
    /// # SAFETY: block is order-aligned, in-range, PMM-owned at call.
    unsafe fn verify_poison(&self, pfn: u64, order: u8) {
        let span = 1u64 << order;
        for k in 0..span {
            // SAFETY: page within the order-o block; PMM-owned at call.
            let p = unsafe { self.backing.page_ptr(Pfn(pfn + k)) };
            // SAFETY: read 16B header from PMM-owned page.
            let m = unsafe { read_u64(p, OFF_POISON) };
            kassert!(m == POISON_MAGIC, "pmm poison mismatch on alloc");
        }
    }

    /// Greedy seed: place largest aligned blocks at `cur..end` onto
    /// free-lists with bitmap bits set. Used by init + region-replay.
    ///
    /// # SAFETY: `cur..end` is in-range, never previously seeded.
    unsafe fn seed_range(&mut self, mut cur: u64, end: u64) {
        while cur < end {
            let remaining = end - cur;
            let mut o: u8 = MAX_ORDER;
            loop {
                let span = 1u64 << o;
                if (cur & (span - 1)) == 0 && span <= remaining { break; }
                if o == 0 { break; }
                o -= 1;
            }
            let span = 1u64 << o;
            // SAFETY: cur..cur+span is order-o aligned, in-range, never seeded.
            unsafe { self.push_free(cur, o) };
            self.bitmap_set(o, cur >> o);
            self.free_count[o as usize] += 1;
            cur += span;
        }
    }
}

// ---------------------------------------------------------------------------
// Local kassert! — bridges to `38` once that crate ships a real impl.
// ---------------------------------------------------------------------------

#[macro_export]
macro_rules! kassert {
    ($cond:expr, $msg:literal) => {{
        if !($cond) { panic!($msg); }
    }};
}

// ---------------------------------------------------------------------------
// Pmm — public API per `10§4`.
// ---------------------------------------------------------------------------

/// PMM owner. Single-instance kernel-wide; constructed in the boot path
/// after the firmware memory map is parsed (`10§6.3`). All access goes
/// through the `Buddy` spinlock per `10§7`.
pub struct Pmm<B: PageBacking> {
    inner: Spinlock<PmmInner<B>, Buddy>,
}

impl<B: PageBacking> Pmm<B> {
    /// Build a PMM from one or more usable physical regions. Each
    /// region is greedy-largest-aligned-block seeded; the union must
    /// not overlap (caller invariant per `10§6.3`).
    ///
    /// # C: O(n + N) where n=regions, N=max_pfn / smallest order
    /// # Ctx: pre-init, single-CPU
    pub fn init(backing: B, regions: &[UsableRegion]) -> KResult<Self> {
        if regions.is_empty() { return Err(Error::OutOfRange); }
        let mut pfn_max: u64 = 0;
        let mut total: u64 = 0;
        for r in regions {
            let end = r.start.0.checked_add(r.len_pfn).ok_or(Error::OutOfRange)?;
            if end > pfn_max { pfn_max = end; }
            total = total.checked_add(r.len_pfn).ok_or(Error::OutOfRange)?;
        }
        // Defensive overlap detection — caller invariant per `10§6.3`,
        // but seeding the same page twice corrupts the free-list, so
        // reject at boot rather than crash later.
        for i in 0..regions.len() {
            let a = &regions[i];
            if a.len_pfn == 0 { continue; }
            let a_end = a.start.0 + a.len_pfn;
            for j in (i + 1)..regions.len() {
                let b = &regions[j];
                if b.len_pfn == 0 { continue; }
                let b_end = b.start.0 + b.len_pfn;
                if a.start.0 < b_end && b.start.0 < a_end {
                    return Err(Error::Overlap);
                }
            }
        }

        let mut bitmaps = [&[][..]; ORDERS];
        for o in 0..ORDERS {
            let blocks = (pfn_max + (1u64 << o) - 1) >> o;
            let words = ((blocks + 63) >> 6) as usize;
            bitmaps[o] = backing.bitmap_storage(o as u8, words);
        }

        let mut inner = PmmInner::<B> {
            backing,
            pfn_max,
            bitmaps,
            free_heads: [PFN_NULL; ORDERS],
            free_count: [0; ORDERS],
            allocated: 0,
            initial_free: total,
        };

        for r in regions {
            // SAFETY: caller-asserted regions disjoint and in-range; the
            // pages have not been touched by any other subsystem yet.
            unsafe { inner.seed_range(r.start.0, r.start.0 + r.len_pfn) };
        }

        Ok(Self { inner: Spinlock::new(inner) })
    }

    /// Reserve `[start, start+len_pfn)` from the boot path. Called
    /// after [`Pmm::init`] for kernel-image / ACPI / framebuffer
    /// ranges that were inside a usable region (`10§6.3`). Reserved
    /// pages count as `allocated` permanently.
    ///
    /// # C: O(len_pfn × MAX_ORDER)
    /// # Ctx: pre-init, single-CPU
    pub fn reserve_early(&self, start: Pfn, len_pfn: u64) -> KResult<()> {
        let mut g = self.inner.lock_irqsave::<NoopIrq>();
        let end = start.0.checked_add(len_pfn).ok_or(Error::OutOfRange)?;
        if end > g.pfn_max { return Err(Error::OutOfRange); }
        let mut p = start.0;
        while p < end {
            // Find smallest containing block currently on a free-list.
            let mut k: Option<u8> = None;
            for o in 0..=MAX_ORDER {
                if g.bitmap_get(o, p >> o) { k = Some(o); break; }
            }
            let Some(mut o) = k else {
                // Page already allocated/reserved by an earlier call,
                // or outside seeded RAM. Skip.
                p += 1;
                continue;
            };
            let mut blk = (p >> o) << o;
            // Remove from free-list at order o.
            // SAFETY: bitmap-truth says blk is on free_list[o].
            unsafe { g.unlink_free(blk, o) };
            g.bitmap_clear(o, blk >> o);
            g.free_count[o as usize] -= 1;
            // Split down to order 0 along the half containing p.
            while o > 0 {
                o -= 1;
                let half = 1u64 << o;
                let buddy = blk + half;
                if p >= buddy {
                    // SAFETY: half is order-o aligned, in-range, not on
                    // any list (just split out).
                    unsafe { g.push_free(blk, o) };
                    g.bitmap_set(o, blk >> o);
                    g.free_count[o as usize] += 1;
                    blk = buddy;
                } else {
                    // SAFETY: buddy is order-o aligned, in-range, not on
                    // any list (just split out).
                    unsafe { g.push_free(buddy, o) };
                    g.bitmap_set(o, buddy >> o);
                    g.free_count[o as usize] += 1;
                }
            }
            // blk now == p; consume it as permanently reserved.
            debug_assert_eq!(blk, p);
            g.allocated += 1;
            p += 1;
        }
        Ok(())
    }

    /// Allocate one buddy block of `order`. Returns the base PFN.
    /// Always picks lower half on split (deterministic) per `10§6.1`.
    /// Verifies poison inside lock; zeros pages outside lock.
    ///
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub fn alloc(&self, order: Order) -> KResult<Pfn> {
        if order.0 > MAX_ORDER { return Err(Error::InvalidOrder); }
        let pfn;
        let o = order.0;
        {
            let mut g = self.inner.lock_irqsave::<NoopIrq>();
            let mut k = o;
            while k <= MAX_ORDER && g.free_heads[k as usize] == PFN_NULL {
                k += 1;
            }
            if k > MAX_ORDER { return Err(Error::NoMem); }
            // SAFETY: k's list is non-empty by the loop exit condition.
            pfn = unsafe { g.pop_free(k) };
            g.bitmap_clear(k, pfn >> k);
            g.free_count[k as usize] -= 1;
            while k > o {
                k -= 1;
                let buddy = pfn + (1u64 << k);
                // SAFETY: buddy is order-k aligned (lower-half pfn at order
                // k+1 ⇒ buddy = pfn + 1<<k); in-range; not on any list.
                unsafe { g.push_free(buddy, k) };
                g.bitmap_set(k, buddy >> k);
                g.free_count[k as usize] += 1;
            }
            // SAFETY: pfn is the popped (and possibly split-down) order-o
            // block; PMM-owned; verify poison before releasing the lock.
            unsafe { g.verify_poison(pfn, o) };
            g.allocated += 1u64 << o;
        }
        // Zero outside the lock per `10§6.1`.
        let span = 1u64 << o;
        for k in 0..span {
            let g = self.inner.lock_irqsave::<NoopIrq>();
            // SAFETY: pfn..pfn+span is the just-allocated block, owned by
            // the caller, no aliasing; PAGE_SIZE_BYTES per page.
            let p = unsafe { g.backing.page_ptr(Pfn(pfn + k)) };
            drop(g);
            // SAFETY: pointer is page-aligned and points to PAGE_SIZE_BYTES
            // of caller-owned memory; no aliasing for the duration.
            unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE_BYTES as usize) };
        }
        Ok(Pfn(pfn))
    }

    /// Free a buddy block; merge with its sibling iteratively up to
    /// `MAX_ORDER` per `10§6.2`. Sibling existence checked via bitmap
    /// (O(1) atomic), NOT free-list walk.
    ///
    /// # SAFETY: `pfn` is aligned to `1<<order` and was returned by a
    /// prior `alloc(order)` (or `reserve_early`-released — not v1).
    /// Double-free is detected by the bitmap-set check at entry.
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub unsafe fn free(&self, pfn: Pfn, order: Order) {
        kassert!(order.0 <= MAX_ORDER, "pmm free invalid order");
        let mut g = self.inner.lock_irqsave::<NoopIrq>();
        let mut p = pfn.0;
        let mut o = order.0;
        kassert!(p < g.pfn_max, "pmm free pfn out of range");
        kassert!(p & ((1u64 << o) - 1) == 0, "pmm free pfn misaligned for order");
        for ck in o..=MAX_ORDER {
            kassert!(!g.bitmap_get(ck, p >> ck), "pmm double free detected by bitmap");
        }
        loop {
            if o == MAX_ORDER { break; }
            let buddy = p ^ (1u64 << o);
            if buddy + (1u64 << o) > g.pfn_max { break; }
            if !g.bitmap_get(o, buddy >> o) { break; }
            // SAFETY: bitmap I3 says buddy is on free_list[o].
            unsafe { g.unlink_free(buddy, o) };
            g.bitmap_clear(o, buddy >> o);
            g.free_count[o as usize] -= 1;
            if buddy < p { p = buddy; }
            o += 1;
        }
        // SAFETY: p..p+(1<<o) is order-o aligned, in-range, not on any
        // free-list (just merged out of it or it's the original).
        unsafe { g.push_free(p, o) };
        g.bitmap_set(o, p >> o);
        g.free_count[o as usize] += 1;
        g.allocated -= 1u64 << order.0;
    }

    /// Total free pages across all orders.
    /// # C: O(MAX_ORDER)
    pub fn free_pages(&self) -> u64 {
        let g = self.inner.lock_irqsave::<NoopIrq>();
        let mut sum = 0u64;
        for o in 0..ORDERS { sum += g.free_count[o] << o; }
        sum
    }

    /// Total allocated pages.
    /// # C: O(1)
    pub fn allocated_pages(&self) -> u64 {
        self.inner.lock_irqsave::<NoopIrq>().allocated
    }

    /// Total pfn span the PMM owns (`pfn_max`).
    /// # C: O(1)
    pub fn pfn_max(&self) -> u64 {
        self.inner.lock_irqsave::<NoopIrq>().pfn_max
    }

    /// Walk every order's bitmap + free-list; panic on invariant
    /// violation. Verifies I1, I3, I4, I6, I7. I2 and I5 are guaranteed
    /// by I1 + I4 + the construction algorithm (no separate check).
    ///
    /// # SAFETY: walks every populated bitmap word and every free-list
    /// node; reads 16B header from each free node's first page.
    /// # C: O(N)
    pub unsafe fn audit(&self) {
        let g = self.inner.lock_irqsave::<NoopIrq>();
        let mut total_free = 0u64;
        for o in 0..ORDERS {
            let order = o as u8;
            let mut n = 0u64;
            let mut cur = g.free_heads[o];
            while cur != PFN_NULL {
                kassert!(g.bitmap_get(order, cur >> o), "I3: free-list node not in bitmap");
                kassert!(cur & ((1u64 << o) - 1) == 0, "I4: free-list node misaligned");
                n += 1;
                // SAFETY: cur on free_list[o] ⇒ PMM-owned page.
                let p = unsafe { g.backing.page_ptr(Pfn(cur)) };
                // SAFETY: read 16B header from PMM-owned page.
                let m = unsafe { read_u64(p, OFF_POISON) };
                kassert!(m == POISON_MAGIC, "I7: poison missing on free node");
                // SAFETY: read next field inside header.
                cur = unsafe { read_u64(p, OFF_NEXT) };
            }
            kassert!(n == g.free_count[o], "I3: free_count vs list-length mismatch");
            let mut bits = 0u64;
            for w in g.bitmaps[o].iter() { bits += w.load(Ordering::Relaxed).count_ones() as u64; }
            kassert!(bits == g.free_count[o], "I1: bitmap pop vs free_count mismatch");
            total_free += g.free_count[o] << o;
        }
        kassert!(total_free + g.allocated == g.initial_free, "I6: total accounting violated");
    }
}

#[cfg(test)]
mod tests;
