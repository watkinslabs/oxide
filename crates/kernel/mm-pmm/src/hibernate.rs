//! PMM-owned hibernation allocation state.
//!
//! The power layer owns image policy. PMM only supplies immutable free-state
//! snapshots and reversible ownership transitions against its buddy truth.

use super::*;
use alloc::vec;
use alloc::vec::Vec;

/// Immutable membership snapshot of PFNs free after every PCP was drained.
pub struct FreePfnSnapshot {
    words: Vec<u64>,
    forbidden: Vec<u64>,
    pfn_max: u64,
    free_pages: u64,
}

/// Allocation-free workspace prepared before device quiesce and populated at
/// the final, IRQ-off image-selection point.
pub struct FreePfnWorkspace {
    words: Vec<u64>,
    forbidden: Vec<u64>,
    pfn_max: u64,
}

impl FreePfnSnapshot {
    /// Whether `pfn` was free at the snapshot point.
    /// # C: O(1)
    pub fn contains(&self, pfn: Pfn) -> bool {
        if pfn.0 >= self.pfn_max { return false; }
        self.words[(pfn.0 >> 6) as usize] & (1u64 << (pfn.0 & 63)) != 0
    }

    /// Whether PMM excluded `pfn` at the same snapshot point. # C: O(1)
    pub fn forbidden(&self, pfn: Pfn) -> bool {
        pfn.0 < self.pfn_max
            && self.forbidden[(pfn.0 >> 6) as usize] & (1u64 << (pfn.0 & 63)) != 0
    }

    /// Number of free base pages represented by this snapshot.
    /// # C: O(1)
    pub fn free_pages(&self) -> u64 { self.free_pages }

    /// Exclusive PFN bound represented by this snapshot.
    /// # C: O(1)
    pub fn pfn_max(&self) -> u64 { self.pfn_max }
}

/// One temporary hibernation frame, exclusively owned until drop.
///
/// Copy pages, safe pages, and exact restore destinations intentionally use
/// the same owner: their role belongs to the power snapshot, while PMM owns
/// only the allocation transition.
pub struct HibernateFrame<'a, B: PageBacking, I: IrqGate = NoopIrq> {
    pmm: &'a Pmm<B, I>,
    pfn: Pfn,
}

/// One saved-continuation state frame which must itself belong to the image.
///
/// Unlike copy, collision, and restore-control frames, this owner deliberately
/// does not set the hibernation-forbidden bit.  It is allocated before the
/// authoritative free snapshot, so ordinary allocated-page truth selects it
/// for persistence while RAII still prevents reuse.
pub struct HibernateSavedFrame<'a, B: PageBacking, I: IrqGate = NoopIrq> {
    pmm: &'a Pmm<B, I>,
    pfn: Pfn,
}

impl<B: PageBacking, I: IrqGate> HibernateSavedFrame<'_, B, I> {
    /// The exclusively held, saveable frame number. # C: O(1)
    pub fn pfn(&self) -> Pfn { self.pfn }

    /// # SAFETY: the caller must retain this sole owner for the access.
    /// # C: O(1)
    pub unsafe fn as_ptr(&self) -> *const u8 {
        // SAFETY: this RAII value owns pfn until its Drop.
        unsafe { self.pmm.page_ptr(self.pfn) as *const u8 }
    }

    /// # SAFETY: the caller must retain this sole owner and exclude aliases.
    /// # C: O(1)
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        // SAFETY: this RAII value owns pfn until its Drop.
        unsafe { self.pmm.page_ptr(self.pfn) }
    }
}

impl<B: PageBacking, I: IrqGate> Drop for HibernateSavedFrame<'_, B, I> {
    fn drop(&mut self) {
        // SAFETY: this value is the sole owner produced by the paired allocator.
        unsafe { self.pmm.free(self.pfn, Order(0)) };
    }
}

impl<B: PageBacking, I: IrqGate> HibernateFrame<'_, B, I> {
    /// The exclusively held frame number.
    /// # C: O(1)
    pub fn pfn(&self) -> Pfn { self.pfn }

    /// Direct-map pointer for reading image bytes.
    ///
    /// # SAFETY: the caller must keep this owner alive and must not read while
    /// another owner mutates the frame.
    /// # C: O(1)
    pub unsafe fn as_ptr(&self) -> *const u8 {
        // SAFETY: this RAII value owns pfn until its Drop.
        unsafe { self.pmm.page_ptr(self.pfn) as *const u8 }
    }

    /// Direct-map pointer for copying image bytes.
    ///
    /// # SAFETY: the caller must not create aliased mutable access to this
    /// frame and must keep this owner alive for the complete access.
    /// # C: O(1)
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        // SAFETY: this RAII value owns pfn until its Drop.
        unsafe { self.pmm.page_ptr(self.pfn) }
    }
}

impl<B: PageBacking, I: IrqGate> Drop for HibernateFrame<'_, B, I> {
    fn drop(&mut self) {
        self.pmm.hibernate_allow(self.pfn);
        // SAFETY: this value is the sole owner produced by alloc or the exact
        // claim transaction, and Drop runs exactly once.
        unsafe { self.pmm.free(self.pfn, Order(0)) };
    }
}

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    pub(super) fn hibernate_forbid(&self, pfn: Pfn) {
        if pfn.0 >= self.pfn_max { return; }
        self.hibernate_forbidden[(pfn.0 >> 6) as usize]
            .fetch_or(1u64 << (pfn.0 & 63), Ordering::Release);
    }

    fn hibernate_allow(&self, pfn: Pfn) {
        if pfn.0 >= self.pfn_max { return; }
        self.hibernate_forbidden[(pfn.0 >> 6) as usize]
            .fetch_and(!(1u64 << (pfn.0 & 63)), Ordering::Release);
    }

    /// Whether PMM permanently reserved or temporarily owns this PFN for hibernation.
    /// # C: O(1)
    pub fn hibernate_pfn_forbidden(&self, pfn: Pfn) -> bool {
        pfn.0 < self.pfn_max && self.hibernate_forbidden[(pfn.0 >> 6) as usize]
            .load(Ordering::Acquire) & (1u64 << (pfn.0 & 63)) != 0
    }

    /// Drain all PCPs and copy the allocator-authoritative free state.
    ///
    /// The bitmap allocation precedes the drain, so no allocation occurs
    /// while buddy ownership is locked. The power transition must already
    /// have frozen allocation-capable peers; that is the cross-PCP exclusion
    /// which makes the drained buddy view a single point-in-time snapshot.
    /// # C: O(pfn_max + CPU_COUNT * NR_ZONES)
    /// # Ctx: blockable hibernation transition; allocation peers quiesced
    /// # Lk: every PCP briefly, then Buddy
    pub fn hibernate_free_workspace(&self) -> FreePfnWorkspace {
        let words = vec![0u64; self.pfn_max.saturating_add(63).wrapping_div(64) as usize];
        let forbidden = vec![0u64; words.len()];
        FreePfnWorkspace { words, forbidden, pfn_max: self.pfn_max }
    }

    /// Populate an early workspace from the final allocator truth without
    /// allocating after device/CPU quiesce. # C: O(pfn_max + CPU_COUNT * NR_ZONES)
    pub fn hibernate_free_snapshot_into(&self, mut workspace: FreePfnWorkspace)
        -> FreePfnSnapshot
    {
        debug_assert_eq!(workspace.pfn_max, self.pfn_max);
        workspace.words.fill(0);
        workspace.forbidden.fill(0);
        self.drain_pcp_below(NR_ZONES - 1);
        let g = self.inner.lock_irqsave::<I>();
        let mut free_pages = 0u64;
        for order in 0..=MAX_ORDER {
            let span = 1u64 << order;
            let blocks = self.pfn_max.saturating_add(span - 1) >> order;
            for index in 0..blocks {
                if !g.bitmap_get(order, index) { continue; }
                let start = index << order;
                let end = core::cmp::min(start.saturating_add(span), self.pfn_max);
                for pfn in start..end {
                    workspace.words[(pfn >> 6) as usize] |= 1u64 << (pfn & 63);
                    free_pages += 1;
                }
            }
        }
        for (index, word) in workspace.forbidden.iter_mut().enumerate() {
            *word = self.hibernate_forbidden[index].load(Ordering::Acquire);
        }
        FreePfnSnapshot { words: workspace.words, forbidden: workspace.forbidden,
            pfn_max: self.pfn_max, free_pages }
    }

    /// Allocate and capture the free-PFN snapshot. # C: O(PFN_max + free blocks)
    pub fn hibernate_free_snapshot(&self) -> FreePfnSnapshot {
        let workspace = self.hibernate_free_workspace();
        self.hibernate_free_snapshot_into(workspace)
    }

    /// Rebuild intrusive free-page links omitted from the physical image.
    /// The saved buddy bitmaps remain authoritative; final snapshotting has
    /// drained every PCP, so no page-body link is consulted. # C: O(bitmap words + free blocks)
    /// # Ctx: restored continuation; one CPU, IRQs off, allocation quiesced
    /// # Lk: each PCP briefly, then Buddy
    pub fn hibernate_restore_free_lists(&self) {
        for zone in 0..NR_ZONES { for mt_index in 0..MIGRATE_TYPES { for cpu in 0..cpu::MAX_CPUS {
            let pcp = self.pcp.list(cpu, zone, MigrateType::from_index(mt_index)).lock_irqsave::<I>();
            kassert!(pcp.count() == 0 && pcp.head() == PFN_NULL,
                "hibernate restore found nonempty saved pcp list");
        }}}
        for count in &self.pcp_free {
            kassert!(count.load(Ordering::Acquire) == 0,
                "hibernate restore found saved pcp accounting");
        }
        for word in self.pcp_bitmap {
            kassert!(word.load(Ordering::Acquire) == 0,
                "hibernate restore found saved pcp bitmap");
        }

        let mut g = self.inner.lock_irqsave::<I>();
        g.free_heads = [[[PFN_NULL; ORDERS]; MIGRATE_TYPES]; NR_ZONES];
        g.free_count = [[[0; ORDERS]; MIGRATE_TYPES]; NR_ZONES];
        let mut by_zone = [0u64; NR_ZONES];
        for order_index in 0..ORDERS {
            let order = order_index as u8;
            for word_index in 0..g.bitmaps[order_index].len() {
                let mut bits = g.bitmaps[order_index][word_index].load(Ordering::Relaxed);
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    let block = (word_index * u64::BITS as usize + bit) as u64;
                    let pfn = block << order;
                    kassert!(pfn < self.pfn_max, "hibernate restore free block out of range");
                    let zone = self.layout.index_of(pfn);
                    kassert!(zone < NR_ZONES, "hibernate restore free block outside zones");
                    let mt = g.migratetype(pfn);
                    // SAFETY: the restored authoritative bitmap names this
                    // disjoint free block; all list heads were cleared above.
                    unsafe { g.push_free(&self.backing, pfn, order, mt) };
                    g.free_count[zone][mt.index()][order_index] += 1;
                    by_zone[zone] += 1u64 << order;
                }
            }
        }
        for zone in 0..NR_ZONES {
            kassert!(self.zone_free[zone].load(Ordering::Acquire) == by_zone[zone],
                "hibernate restore free accounting mismatch");
        }
    }

    /// Allocate one copy/safe/control frame with reversible nosave ownership.
    /// # C: O(NR_ZONES * MAX_ORDER)
    /// # Ctx: blockable hibernation setup; may enter reclaim
    pub fn alloc_hibernate_frame(&self) -> KResult<HibernateFrame<'_, B, I>> {
        self.alloc(Order(0)).map(|pfn| {
            self.hibernate_forbid(pfn);
            HibernateFrame { pmm: self, pfn }
        })
    }

    /// Allocate the saved CPU-state page without excluding it from the image.
    /// This must precede the free snapshot; allocating it later would make it
    /// indistinguishable from a page which was free at snapshot time.
    /// # C: O(NR_ZONES * MAX_ORDER)
    /// # Ctx: blockable hibernation setup; may enter reclaim
    pub fn alloc_hibernate_saved_frame(&self) -> KResult<HibernateSavedFrame<'_, B, I>> {
        self.alloc(Order(0)).map(|pfn| HibernateSavedFrame { pmm: self, pfn })
    }

    /// Atomically claim exactly `pfn` if it is currently globally free.
    ///
    /// `None` is the collision result: the PFN is out of range, allocated,
    /// reserved, or absent. The transition never substitutes another page.
    /// The caller must have quiesced allocation peers before calling.
    /// # C: O(CPU_COUNT * NR_ZONES + MAX_ORDER)
    /// # Ctx: blockable hibernation transition; allocation peers quiesced
    /// # Lk: every PCP briefly, then Buddy
    pub fn claim_hibernate_pfn(&self, pfn: Pfn) -> Option<HibernateFrame<'_, B, I>> {
        if pfn.0 >= self.pfn_max { return None; }
        self.drain_pcp_below(NR_ZONES - 1);
        let zi = self.layout.index_of(pfn.0);
        if zi >= NR_ZONES { return None; }
        let mut g = self.inner.lock_irqsave::<I>();
        let mut found = None;
        for order in 0..=MAX_ORDER {
            if g.bitmap_get(order, pfn.0 >> order) {
                found = Some(order);
                break;
            }
        }
        let order = found?;
        let mut base = (pfn.0 >> order) << order;
        let mt = g.migratetype(base);
        // SAFETY: the bitmap identifies `base` as a node on this exact list.
        unsafe { g.verify_poison(&self.backing, base) };
        // SAFETY: the same bitmap-truth identifies the derived list membership.
        unsafe { g.unlink_free(&self.backing, base, order, mt) };
        g.bitmap_clear(order, base >> order);
        g.free_count[zi][mt.index()][order as usize] -= 1;
        let mut split = order;
        while split > 0 {
            split -= 1;
            let half = 1u64 << split;
            let sibling = if pfn.0 < base + half { base + half } else {
                let old = base;
                base += half;
                old
            };
            // SAFETY: sibling is the unlisted half not containing target.
            unsafe { g.push_free(&self.backing, sibling, split, mt) };
            g.bitmap_set(split, sibling >> split);
            g.free_count[zi][mt.index()][split as usize] += 1;
        }
        debug_assert_eq!(base, pfn.0);
        g.allocated += 1;
        g.alloc_events += 1;
        g.alloc_event_pages += 1;
        drop(g);
        self.zone_free[zi].fetch_sub(1, Ordering::AcqRel);
        self.hibernate_forbid(pfn);
        Some(HibernateFrame { pmm: self, pfn })
    }
}
