use super::*;
use super::free_node::*;

// ---------------------------------------------------------------------------
// PmmInner — protected by the Buddy spinlock.
// ---------------------------------------------------------------------------

// Backing is held outside the lock so `Pmm::page_ptr` is lock-free
// and slab (Slab class, rank 10) can safely call it while holding its
// own spinlock — taking the lower-rank Buddy lock at that point would
// violate the partial order in `06§3.6`. PageBacking trait methods are
// pure pointer arithmetic over the boot-allocated backing structures
// and are inherently `Send + Sync`.
pub(super) struct PmmInner {
    pub(super) pfn_max: u64,                                    // exclusive upper bound
    pub(super) bitmaps: [&'static [AtomicU64]; ORDERS],
    pub(super) free_heads: [u64; ORDERS],
    pub(super) free_count: [u64; ORDERS],
    pub(super) allocated: u64,
    /// Permanently consumed boot pages.  These stay part of the allocator's
    /// `allocated` invariant but are reported separately from runtime users.
    pub(super) reserved: u64,
    pub(super) initial_free: u64,
    /// Successful runtime buddy operations, recorded under the same lock as
    /// the state transition so observation cannot race a half-transition.
    pub(super) alloc_events: u64,
    pub(super) alloc_event_pages: u64,
    pub(super) free_events: u64,
    pub(super) free_event_pages: u64,
}

impl PmmInner {
    pub(super) fn bitmap_get(&self, order: u8, idx: u64) -> bool {
        let word = (idx >> 6) as usize;
        let bit = (idx & 63) as u32;
        (self.bitmaps[order as usize][word].load(Ordering::Relaxed) >> bit) & 1 == 1
    }

    pub(super) fn bitmap_set(&self, order: u8, idx: u64) {
        let word = (idx >> 6) as usize;
        let bit = (idx & 63) as u32;
        self.bitmaps[order as usize][word].fetch_or(1u64 << bit, Ordering::Relaxed);
    }

    pub(super) fn bitmap_clear(&self, order: u8, idx: u64) {
        let word = (idx >> 6) as usize;
        let bit = (idx & 63) as u32;
        self.bitmaps[order as usize][word].fetch_and(!(1u64 << bit), Ordering::Relaxed);
    }

    /// Stamp poison + order on every page of the order-o block at `pfn`.
    ///
    /// # SAFETY: block is order-aligned, in-range, currently NOT on any
    /// free-list; pages are PMM-owned at call site; backing is the live
    /// PageBacking impl handed to `Pmm::init`.
    pub(super) unsafe fn stamp_block<B: PageBacking>(
        &self,
        backing: &B,
        pfn: u64,
        order: u8,
        head_next: u64,
        head_prev: u64,
    ) {
        let span = 1u64 << order;
        for k in 0..span {
            // SAFETY: page within the order-o block; PMM-owned per fn contract.
            let p = unsafe { backing.page_ptr(Pfn(pfn + k)) };
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
    pub(super) unsafe fn push_free<B: PageBacking>(&mut self, backing: &B, pfn: u64, order: u8) {
        let head = self.free_heads[order as usize];
        // SAFETY: pfn block PMM-owned per fn contract.
        unsafe { self.stamp_block(backing, pfn, order, head, PFN_NULL) };
        if head != PFN_NULL {
            // SAFETY: old head's page is on the free-list ⇒ PMM-owned.
            let hp = unsafe { backing.page_ptr(Pfn(head)) };
            // SAFETY: write old head's prev field inside its header.
            unsafe { write_u64(hp, OFF_PREV, pfn) };
        }
        self.free_heads[order as usize] = pfn;
    }

    /// Pop head of free_list[order]. Caller updates bitmap + count.
    ///
    /// # SAFETY: free_list[order] is non-empty.
    pub(super) unsafe fn pop_free<B: PageBacking>(&mut self, backing: &B, order: u8) -> u64 {
        let head = self.free_heads[order as usize];
        debug_assert!(head != PFN_NULL);
        // SAFETY: head on free-list ⇒ PMM-owned page.
        let hp = unsafe { backing.page_ptr(Pfn(head)) };
        // SAFETY: header lives in first 32B of a PMM-owned page.
        let mut next = unsafe { read_u64(hp, OFF_NEXT) };
        // SURVIVAL GUARD (always on): a corrupt (overwritten-while-free) head
        // node's `next` link would #GP the pop below. Clamp out-of-range links
        // to PFN_NULL so the allocator survives (list truncated, frames leak) —
        // logged upstream. Keeps the boot alive through the free-while-mapped bug.
        if next != PFN_NULL && next >= self.pfn_max {
            klog::write_raw(b"[FREELIST-HEAL] pop bad next="); klog::write_hex_u64(next);
            klog::write_raw(b" head="); klog::write_hex_u64(head); klog::write_raw(b"\n");
            next = PFN_NULL;
        }
        // debug-cow probe 1 (FREELIST CANARY): a free node's `next` link is
        // either PFN_NULL or an in-range PFN. A `next` that is neither means
        // the freed frame's FreeNode header was overwritten while it sat on
        // the free list (a stale-TLB write, a write-while-free, or a buddy
        // desync) — the same aliasing class as a double-alloc, seen from the
        // link side. Name the corrupted node by its PA.
        #[cfg(feature = "debug-cow")]
        if next != PFN_NULL && next >= self.pfn_max {
            klog::write_raw(b"[FREELIST-CORRUPT] pa=");
            klog::write_hex_u64(head * PAGE_SIZE_BYTES);
            klog::write_raw(b" bad-next=");
            klog::write_hex_u64(next);
            klog::write_raw(b"\n");
        }
        if next != PFN_NULL {
            // SAFETY: `next` is on the free-list ⇒ PMM-owned page.
            let np = unsafe { backing.page_ptr(Pfn(next)) };
            // SAFETY: write into next-node's prev field; PMM-owned page.
            unsafe { write_u64(np, OFF_PREV, PFN_NULL) };
        }
        self.free_heads[order as usize] = next;
        head
    }

    /// Remove `pfn` from free_list[order] (used during merge / reserve).
    ///
    /// # SAFETY: `pfn` is currently on free_list[order]; page PMM-owned.
    pub(super) unsafe fn unlink_free<B: PageBacking>(&mut self, backing: &B, pfn: u64, order: u8) {
        // SAFETY: pfn on free-list ⇒ PMM-owned page.
        let p = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: header read inside owned page.
        let mut next = unsafe { read_u64(p, OFF_NEXT) };
        // SAFETY: header read inside owned page.
        let mut prev = unsafe { read_u64(p, OFF_PREV) };
        // SURVIVAL GUARD (always on, Linux-style defensive mm): a free node whose
        // link is neither PFN_NULL nor an in-range pfn was overwritten while free
        // (free-while-mapped). Dereferencing it below would #GP and kill the
        // boot; instead clamp the bad link to PFN_NULL (truncating the list —
        // some frames leak) so the kernel SURVIVES and the greeter can still come
        // up. The corruption is still logged upstream (FWM-CORRUPT / poison).
        if next != PFN_NULL && next >= self.pfn_max {
            klog::write_raw(b"[FREELIST-HEAL] unlink bad next="); klog::write_hex_u64(next);
            klog::write_raw(b" at pfn="); klog::write_hex_u64(pfn); klog::write_raw(b"\n");
            next = PFN_NULL;
        }
        if prev != PFN_NULL && prev >= self.pfn_max {
            klog::write_raw(b"[FREELIST-HEAL] unlink bad prev="); klog::write_hex_u64(prev);
            klog::write_raw(b" at pfn="); klog::write_hex_u64(pfn); klog::write_raw(b"\n");
            prev = PFN_NULL;
        }
        if prev == PFN_NULL {
            self.free_heads[order as usize] = next;
        } else {
            // SAFETY: prev on free-list ⇒ PMM-owned page.
            let pp = unsafe { backing.page_ptr(Pfn(prev)) };
            // SAFETY: writing prev's next field inside its header.
            unsafe { write_u64(pp, OFF_NEXT, next) };
        }
        if next != PFN_NULL {
            // SAFETY: next on free-list ⇒ PMM-owned page.
            let np = unsafe { backing.page_ptr(Pfn(next)) };
            // SAFETY: writing next's prev field inside its header.
            unsafe { write_u64(np, OFF_PREV, prev) };
        }
    }

    /// Verify poison on every page of the order-o block at `pfn`.
    ///
    /// # SAFETY: block is order-aligned, in-range, PMM-owned at call.
    pub(super) unsafe fn verify_poison<B: PageBacking>(&self, backing: &B, pfn: u64, order: u8) {
        let span = 1u64 << order;
        for k in 0..span {
            // SAFETY: page within the order-o block; PMM-owned at call.
            let p = unsafe { backing.page_ptr(Pfn(pfn + k)) };
            // SAFETY: read 16B header from PMM-owned page.
            let m = unsafe { read_u64(p, OFF_POISON) };
            kassert!(m == POISON_MAGIC, "pmm poison mismatch on alloc");
        }
    }

    /// Greedy seed: place largest aligned blocks at `cur..end` onto
    /// free-lists with bitmap bits set. Used by init + region-replay.
    ///
    /// # SAFETY: `cur..end` is in-range, never previously seeded.
    pub(super) unsafe fn seed_range<B: PageBacking>(&mut self, backing: &B, mut cur: u64, end: u64) {
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
            unsafe { self.push_free(backing, cur, o) };
            self.bitmap_set(o, cur >> o);
            self.free_count[o as usize] += 1;
            cur += span;
        }
    }
}
