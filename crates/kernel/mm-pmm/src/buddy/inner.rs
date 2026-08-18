use super::*;
use super::free_node::*;
use super::pageblock::PageblockTypes;

// Lock-protected buddy state. Free-list membership is split first by zone,
// then by migratetype, then by order; the bitmap remains the sole truth for
// whether an order block is globally free.
pub(super) struct PmmInner {
    pub(super) pfn_max: u64,
    pub(super) bitmaps: [&'static [AtomicU64]; ORDERS],
    pub(super) layout: ZoneLayout,
    pub(super) zonelist: Zonelist,
    pub(super) pageblocks: PageblockTypes,
    pub(super) free_heads: [[[u64; ORDERS]; MIGRATE_TYPES]; NR_ZONES],
    pub(super) free_count: [[[u64; ORDERS]; MIGRATE_TYPES]; NR_ZONES],
    pub(super) managed: [u64; NR_ZONES],
    pub(super) present: [u64; NR_ZONES],
    pub(super) spanned: [u64; NR_ZONES],
    pub(super) reserve: LowmemReserve,
    pub(super) wmark: [ZoneWatermarks; NR_ZONES],
    pub(super) tunables: Option<crate::watermark::WatermarkTunables>,
    pub(super) allocated: u64,
    pub(super) reserved: u64,
    pub(super) initial_free: u64,
    pub(super) alloc_events: u64,
    pub(super) alloc_event_pages: u64,
    pub(super) free_events: u64,
    pub(super) free_event_pages: u64,
}

impl PmmInner {
    /// Re-derive the allocation-gate values from the final zone totals.
    /// # C: O(NR_ZONES^2)
    pub(super) fn recompute_derived(&mut self) -> Option<(u64, ZoneWatermarks)> {
        self.reserve = lowmem_reserve(self.managed, DEFAULT_LOWMEM_RESERVE_RATIO);
        let total: u64 = self.managed.iter().sum();
        let tunables = self.tunables?;
        let mut aggregate = ZoneWatermarks::default();
        for zi in 0..NR_ZONES {
            let cap = zi == ZoneType::Movable.index();
            let wmark = crate::watermark::derive_zone_watermarks(self.managed[zi], total, tunables, PAGE_SIZE_BYTES, cap);
            self.wmark[zi] = wmark;
            aggregate.min += wmark.min; aggregate.low += wmark.low;
            aggregate.high += wmark.high; aggregate.promo += wmark.promo;
        }
        Some((total, aggregate))
    }

    /// Zone slot owning `pfn`, with a terminal slot for malformed callers.
    /// # C: O(NR_ZONES)
    pub(super) fn zi(&self, pfn: u64) -> usize {
        let index = self.layout.index_of(pfn);
        if index < NR_ZONES { index } else { NR_ZONES - 1 }
    }

    /// Pageblock mobility type that owns a returned allocation. # C: O(1)
    pub(super) fn migratetype(&self, pfn: u64) -> MigrateType { self.pageblocks.get(pfn) }

    pub(super) fn bitmap_get(&self, order: u8, index: u64) -> bool {
        let word = (index >> 6) as usize;
        let bit = (index & 63) as u32;
        (self.bitmaps[order as usize][word].load(Ordering::Relaxed) >> bit) & 1 == 1
    }

    pub(super) fn bitmap_set(&self, order: u8, index: u64) {
        let word = (index >> 6) as usize;
        let bit = (index & 63) as u32;
        self.bitmaps[order as usize][word].fetch_or(1u64 << bit, Ordering::Relaxed);
    }

    pub(super) fn bitmap_clear(&self, order: u8, index: u64) {
        let word = (index >> 6) as usize;
        let bit = (index & 63) as u32;
        self.bitmaps[order as usize][word].fetch_and(!(1u64 << bit), Ordering::Relaxed);
    }

    /// # SAFETY: `pfn` is a free block head exclusively owned by PMM.
    unsafe fn stamp_block<B: PageBacking>(&self, backing: &B, pfn: u64, order: u8, next: u64, prev: u64) {
        // SAFETY: caller established that pfn names an owned block head.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: the complete intrusive header lives at the start of pfn.
        unsafe {
            write_u64(page, OFF_POISON, POISON_MAGIC);
            write_u8(page, OFF_ORDER, order);
            for i in 1..8 { write_u8(page, OFF_ORDER + i, 0); }
            write_u64(page, OFF_NEXT, next);
            write_u64(page, OFF_PREV, prev);
        }
    }

    /// Push a block onto exactly its zone and pageblock-type free list.
    /// # SAFETY: `pfn` is not free and the caller owns its complete span.
    pub(super) unsafe fn push_free<B: PageBacking>(&mut self, backing: &B, pfn: u64, order: u8, mt: MigrateType) {
        let zone = self.zi(pfn);
        kassert!(self.migratetype(pfn) == mt, "pmm free block wrong migratetype");
        let head = self.free_heads[zone][mt.index()][order as usize];
        // SAFETY: caller owns pfn and it is not published on a free list.
        unsafe { self.stamp_block(backing, pfn, order, head, PFN_NULL) };
        if head != PFN_NULL {
            // SAFETY: the previous head is on this free list.
            let page = unsafe { backing.page_ptr(Pfn(head)) };
            // SAFETY: update the prior head's intrusive backward link.
            unsafe { write_u64(page, OFF_PREV, pfn) };
        }
        self.free_heads[zone][mt.index()][order as usize] = pfn;
    }

    /// Pop one block from a selected free list.
    /// # SAFETY: the selected list is non-empty and caller holds Buddy.
    pub(super) unsafe fn pop_free<B: PageBacking>(&mut self, backing: &B, zone: usize, order: u8, mt: MigrateType) -> u64 {
        let head = self.free_heads[zone][mt.index()][order as usize];
        debug_assert!(head != PFN_NULL);
        // SAFETY: head belongs to the selected intrusive free list.
        let page = unsafe { backing.page_ptr(Pfn(head)) };
        // SAFETY: read the stable intrusive links before unlinking head.
        let (next, prev) = unsafe { (read_u64(page, OFF_NEXT), read_u64(page, OFF_PREV)) };
        kassert!(prev == PFN_NULL, "pmm free-list head prev mismatch");
        kassert!(next == PFN_NULL || next < self.pfn_max, "pmm free-list next out of range");
        if next != PFN_NULL {
            kassert!(next != head, "pmm free-list self link");
            kassert!(self.zi(next) == zone, "pmm free-list next wrong zone");
            kassert!(self.migratetype(next) == mt, "pmm free-list next wrong migratetype");
            // SAFETY: next is another node on this selected list.
            let next_page = unsafe { backing.page_ptr(Pfn(next)) };
            // SAFETY: read/write only next's intrusive header.
            let next_prev = unsafe { read_u64(next_page, OFF_PREV) };
            kassert!(next_prev == head, "pmm free-list next back-link mismatch");
            unsafe { write_u64(next_page, OFF_PREV, PFN_NULL) };
        }
        self.free_heads[zone][mt.index()][order as usize] = next;
        head
    }

    /// Remove a known block from its selected free list.
    /// # SAFETY: `pfn` is on the named list and caller holds Buddy.
    pub(super) unsafe fn unlink_free<B: PageBacking>(&mut self, backing: &B, pfn: u64, order: u8, mt: MigrateType) {
        let zone = self.zi(pfn);
        kassert!(self.migratetype(pfn) == mt, "pmm unlink wrong migratetype");
        // SAFETY: caller proved pfn is a node on a PMM free list.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: its intrusive header is initialized and stable under Buddy.
        let (next, prev) = unsafe { (read_u64(page, OFF_NEXT), read_u64(page, OFF_PREV)) };
        kassert!(next == PFN_NULL || next < self.pfn_max, "pmm free-list next out of range");
        kassert!(prev == PFN_NULL || prev < self.pfn_max, "pmm free-list prev out of range");
        if prev == PFN_NULL {
            kassert!(self.free_heads[zone][mt.index()][order as usize] == pfn, "pmm free-list head mismatch");
            self.free_heads[zone][mt.index()][order as usize] = next;
        } else {
            kassert!(self.zi(prev) == zone && self.migratetype(prev) == mt, "pmm free-list prev wrong class");
            // SAFETY: prev is a peer node on this list.
            let prev_page = unsafe { backing.page_ptr(Pfn(prev)) };
            // SAFETY: update prev's forward link inside its header.
            unsafe { write_u64(prev_page, OFF_NEXT, next) };
        }
        if next != PFN_NULL {
            kassert!(self.zi(next) == zone && self.migratetype(next) == mt, "pmm free-list next wrong class");
            // SAFETY: next is a peer node on this list.
            let next_page = unsafe { backing.page_ptr(Pfn(next)) };
            // SAFETY: update next's backward link inside its header.
            unsafe { write_u64(next_page, OFF_PREV, prev) };
        }
    }

    /// # SAFETY: `pfn` is the head of a globally free block.
    pub(super) unsafe fn verify_poison<B: PageBacking>(&self, backing: &B, pfn: u64) {
        // SAFETY: caller established pfn is a PMM free-list head.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: inspect the fixed header before allocation overwrites it.
        kassert!(unsafe { read_u64(page, OFF_POISON) } == POISON_MAGIC, "pmm poison mismatch on alloc");
    }

    /// # SAFETY: `start..end` is unseeded usable memory.
    pub(super) unsafe fn seed_range<B: PageBacking>(&mut self, backing: &B, start: u64, end: u64) {
        for zone in 0..NR_ZONES {
            let span = self.layout.span_at(zone);
            let lo = core::cmp::max(start, span.start_pfn);
            let hi = core::cmp::min(end, span.end_pfn);
            if hi > lo {
                // SAFETY: this zone-clipped interval remains unseeded.
                unsafe { self.seed_within_zone(backing, zone, lo, hi) };
            }
        }
    }

    /// # SAFETY: `cur..end` is unseeded and wholly inside `zone`.
    unsafe fn seed_within_zone<B: PageBacking>(&mut self, backing: &B, zone: usize, mut cur: u64, end: u64) {
        while cur < end {
            let mut order = MAX_ORDER;
            while order > 0 {
                let span = 1u64 << order;
                if cur & (span - 1) == 0 && span <= end - cur { break; }
                order -= 1;
            }
            let span = 1u64 << order;
            let mt = self.migratetype(cur);
            // SAFETY: cur names a new aligned block in this unseeded range.
            unsafe { self.push_free(backing, cur, order, mt) };
            self.bitmap_set(order, cur >> order);
            self.free_count[zone][mt.index()][order as usize] += 1;
            self.managed[zone] += span;
            self.present[zone] += span;
            cur += span;
        }
    }

    /// Remove one block of `current_order` then split it to `order`, keeping
    /// all remainders on `mt`'s list. # SAFETY: caller holds Buddy.
    unsafe fn take_from_order<B: PageBacking>(&mut self, backing: &B, zone: usize, order: u8, current_order: u8, mt: MigrateType) -> u64 {
        // SAFETY: caller selected a non-empty list at current_order.
        let pfn = unsafe { self.pop_free(backing, zone, current_order, mt) };
        self.bitmap_clear(current_order, pfn >> current_order);
        self.free_count[zone][mt.index()][current_order as usize] -= 1;
        let mut split = current_order;
        while split > order {
            split -= 1;
            let buddy = pfn + (1u64 << split);
            // SAFETY: buddy is an unlisted half of the selected free block.
            unsafe { self.push_free(backing, buddy, split, mt) };
            self.bitmap_set(split, buddy >> split);
            self.free_count[zone][mt.index()][split as usize] += 1;
        }
        pfn
    }

    /// Claim a whole free fallback block before splitting it. Claiming keeps
    /// future frees in the requester's class instead of permanently polluting
    /// a movable pageblock with unmovable allocations.
    unsafe fn claim_fallback<B: PageBacking>(&mut self, backing: &B, zone: usize, order: u8, requested: MigrateType, fallback: MigrateType) -> Option<u64> {
        let minimum = order.max(crate::zone::PAGEBLOCK_ORDER);
        for current_order in (minimum..=MAX_ORDER).rev() {
            if self.free_heads[zone][fallback.index()][current_order as usize] == PFN_NULL { continue; }
            // SAFETY: the check above proved this selected free list non-empty.
            let pfn = unsafe { self.pop_free(backing, zone, current_order, fallback) };
            self.bitmap_clear(current_order, pfn >> current_order);
            self.free_count[zone][fallback.index()][current_order as usize] -= 1;
            self.pageblocks.set_range(pfn, pfn + (1u64 << current_order), requested);
            let mut split = current_order;
            while split > order {
                split -= 1;
                let buddy = pfn + (1u64 << split);
                // SAFETY: buddy remains an unlisted half of the claimed block.
                unsafe { self.push_free(backing, buddy, split, requested) };
                self.bitmap_set(split, buddy >> split);
                self.free_count[zone][requested.index()][split as usize] += 1;
            }
            return Some(pfn);
        }
        None
    }

    /// Take a block from the preferred list, then claim a complete fallback
    /// pageblock, then finally steal one fallback block without retyping it.
    /// # SAFETY: caller holds Buddy and `zone` is a valid slot.
    pub(super) unsafe fn take_block<B: PageBacking>(&mut self, backing: &B, zone: usize, order: u8, requested: MigrateType) -> Option<u64> {
        for current_order in order..=MAX_ORDER {
            if self.free_heads[zone][requested.index()][current_order as usize] != PFN_NULL {
                // SAFETY: the selected preferred list is non-empty.
                return Some(unsafe { self.take_from_order(backing, zone, order, current_order, requested) });
            }
        }
        for fallback in requested.fallbacks() {
            // SAFETY: caller holds Buddy; claim_fallback preserves list truth.
            if let Some(pfn) = unsafe { self.claim_fallback(backing, zone, order, requested, fallback) } { return Some(pfn); }
        }
        for fallback in requested.fallbacks() {
            for current_order in order..=MAX_ORDER {
                if self.free_heads[zone][fallback.index()][current_order as usize] != PFN_NULL {
                    // SAFETY: the selected fallback list is non-empty.
                    return Some(unsafe { self.take_from_order(backing, zone, order, current_order, fallback) });
                }
            }
        }
        None
    }

    /// Aggregate free blocks by order across mobility classes. Watermarks
    /// measure total reclaimable capacity, not one particular class.
    /// # C: O(types×orders)
    pub(super) fn free_area(&self, zone: usize) -> [u64; ORDERS] {
        let mut out = [0u64; ORDERS];
        for mt in 0..MIGRATE_TYPES { for order in 0..ORDERS { out[order] += self.free_count[zone][mt][order]; } }
        out
    }

    /// Free base pages on every migratetype list in one zone. # C: O(types×orders)
    pub(super) fn zone_free_pages(&self, zone: usize) -> u64 {
        let mut pages = 0u64;
        for mt in 0..MIGRATE_TYPES { for order in 0..ORDERS { pages += self.free_count[zone][mt][order] << order; } }
        pages
    }
}
