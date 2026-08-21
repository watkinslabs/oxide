use super::*;
use super::inner::PmmInner;
use super::pcp::{PcpStorage, PcpZoneConfig};
use super::pageblock::PageblockTypes;

/// PMM owner. Single-instance kernel-wide; constructed in the boot path
/// after the firmware memory map is parsed (`10§6.3`). Global buddy-list
/// transitions use the `Buddy` spinlock, while order-0 pagesets are separately
/// IRQ-locked per CPU and zone. Generic over `IrqGate` per `06§3.1`: kernel
/// targets pass `hal_x86_64::X86IrqGate` /
/// `hal_aarch64::ArmIrqGate` to actually disable IRQs around the lock;
/// hosted tests use `NoopIrq`.
pub struct Pmm<B: PageBacking, I: IrqGate = NoopIrq> {
    /// Backing held outside the lock so `page_ptr` is lock-free.
    /// PageBacking::page_ptr is pure pointer arithmetic; concurrent
    /// callers see the same address. Higher-rank consumers (slab at
    /// rank Slab=10) can safely call `page_ptr` while holding their
    /// own spinlock without violating `06§3.6` partial order.
    pub(super) backing: B,
    pub(super) inner: Spinlock<PmmInner, Buddy>,
    /// Immutable copies of the global allocation topology. Per-CPU order-0
    /// allocation reads these without taking the buddy lock.
    pub(super) pfn_max: u64,
    pub(super) layout: ZoneLayout,
    pub(super) zonelist: Zonelist,
    pub(super) pageblocks: PageblockTypes,
    /// Mergeable buddy bitmaps remain authoritative for the global lists.
    /// The distinct PCP bitmap records pages that have left those lists but
    /// are still free in one CPU's cache.
    pub(super) buddy_bitmaps: [&'static [AtomicU64]; ORDERS],
    pub(super) pcp_bitmap: &'static [AtomicU64],
    pub(super) hibernate_forbidden: &'static [AtomicU64],
    pub(super) pcp: &'static PcpStorage,
    /// Exact free-page counters include both global buddy blocks and cached
    /// order-0 pages. They are the lock-free watermark input for the PCP
    /// allocation path.
    pub(super) zone_free: [AtomicU64; NR_ZONES],
    pub(super) pcp_free: [AtomicU64; NR_ZONES],
    pub(super) pcp_zone: [PcpZoneConfig; NR_ZONES],
    /// PCP-originated external allocations/frees. The global counters stay
    /// beneath `inner`; snapshots combine the two transition sources.
    pub(super) pcp_alloc_events: AtomicU64,
    pub(super) pcp_alloc_event_pages: AtomicU64,
    pub(super) pcp_free_events: AtomicU64,
    pub(super) pcp_free_event_pages: AtomicU64,
    pub(super) _i: PhantomData<fn() -> I>,
}

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {    /// Allocate one buddy block of `order`. Returns the base PFN.
    /// Always picks lower half on split (deterministic) per `10§6.1`.
    /// Verifies the head free-node inside lock; zeros pages outside lock.
    ///
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: pageset for a local order-0 hit; Buddy for refill or larger blocks
    pub fn alloc(&self, order: Order) -> KResult<Pfn> {
        self.alloc_gfp(order, 0)
    }

    /// Allocate one buddy block of `order` for an allocation whose zone bits
    /// are `gfp`. The bits name the highest zone the block may come from; the
    /// walk descends from there and can never rise above it, so a bounded
    /// request that cannot be met fails instead of escaping its bound.
    ///
    /// # C: O(NR_ZONES × MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: pageset for a local order-0 hit; Buddy for refill or larger blocks
    pub fn alloc_gfp(&self, order: Order, gfp: u32) -> KResult<Pfn> {
        let (hi, mt) = self.alloc_gfp_prepare(order, gfp)?;
        let mut r = self.alloc_inner_zoned(order, hi, AllocWmark::Low, mt);
        // Exhaustion is not the answer until reclaim and the out-of-memory
        // selector have both been given their turn: any allocation that
        // cannot be satisfied enters the slowpath, not only a user fault.
        if matches!(r, Err(Error::NoMem)) { r = self.alloc_slowpath(order, hi, gfp, mt); }
        self.finish_allocation(r)
    }

    /// Allocate without direct reclaim or out-of-memory selection. This is
    /// the PMM equivalent of a NOWAIT request: callers that cannot enter the
    /// task/reclaim path receive `NoMem` after the ordinary low-watermark
    /// zonelist walk.
    ///
    /// # C: O(NR_ZONES × MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off; does not sleep
    /// # Lk: pageset for a local order-0 hit; Buddy for refill or larger blocks
    pub(crate) fn alloc_gfp_nowait(&self, order: Order, gfp: u32) -> KResult<Pfn> {
        let (hi, mt) = self.alloc_gfp_args(gfp)?;
        match self.alloc_inner_zoned(order, hi, AllocWmark::Low, mt) {
            Ok(pfn) => {
                hal::zerotrap::trap_buddy(pfn.0 * hal::PAGE_SIZE_BYTES, b"ALLOC");
                Ok(pfn)
            }
            Err(e) => Err(e),
        }
    }

    fn alloc_gfp_prepare(&self, order: Order, gfp: u32) -> KResult<(usize, MigrateType)> {
        let (hi, mt) = self.alloc_gfp_args(gfp)?;
        // Preserve the allocator ABI: invalid orders are rejected by
        // `alloc_inner` before any order-derived arithmetic is evaluated.
        if order.0 <= MAX_ORDER {
            crate::watermark::before_allocation(self.free_pages(), 1u64 << order.0);
        }
        Ok((hi, mt))
    }

    fn alloc_gfp_args(&self, gfp: u32) -> KResult<(usize, MigrateType)> {
        let Ok(zone) = crate::zone::gfp_zone(gfp) else { return Err(Error::InvalidOrder) };
        let Ok(mt) = crate::zone::gfp_migratetype(gfp) else { return Err(Error::InvalidOrder) };
        Ok((zone.index(), mt))
    }

    fn finish_allocation(&self, r: KResult<Pfn>) -> KResult<Pfn> {
        match r {
            Ok(pfn) => {
                crate::watermark::after_allocation(self.free_pages());
                hal::zerotrap::trap_buddy(pfn.0 * hal::PAGE_SIZE_BYTES, b"ALLOC");
                Ok(pfn)
            }
            Err(e) => Err(e),
        }
    }

    /// Allocate one buddy block wholly below `max_exclusive`.
    ///
    /// A bus-master bound is not a second allocator. It is resolved to the
    /// zone whose top it falls at or below and then handed to the ordinary
    /// allocation, so the bounded request is measured against the same
    /// watermark, owes the same lowmem reserve and enters the same reclaim
    /// and out-of-memory retry as every other request. A block that still
    /// lands outside the bound — which only a bound cutting through the
    /// middle of a zone can produce — is returned and the request retried one
    /// zone lower, terminating after the narrowest zone.
    ///
    /// # C: O(3 × NR_ZONES × MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub fn alloc_below(&self, order: Order, max_exclusive: Pfn) -> KResult<Pfn> {
        if order.0 > MAX_ORDER { return Err(Error::InvalidOrder); }
        let limit = max_exclusive.0;
        let span = 1u64 << order.0;
        if limit < span { return Err(Error::NoMem); }
        let layout = self.inner.lock_irqsave::<I>().layout;
        let mut gfp = crate::zone::gfp_for_pfn_limit(&layout, limit);
        loop {
            let pfn = self.alloc_gfp(order, gfp)?;
            if pfn.0.checked_add(span).is_some_and(|end| end <= limit) { return Ok(pfn); }
            // SAFETY: `pfn` is this call's own order-`order` allocation. It has
            // not been returned to any caller and no other owner exists, so
            // this is its one and only free.
            unsafe { self.free(pfn, order) };
            let Some(next) = crate::zone::narrow_zone_bits(gfp) else { return Err(Error::NoMem); };
            gfp = next;
        }
    }

    /// Reclaim/kill retry loop taken when the fast path found no block.
    /// Policy lives in `crate::oom_entry`; this only supplies the three
    /// actions it drives.
    /// # C: bounded retries; # Ctx: blockable only; # Sleeps: yes
    fn alloc_slowpath(&self, order: Order, hi: usize, gfp: u32, mt: MigrateType) -> KResult<Pfn> {
        // The first thing the slowpath does, before deciding whether this
        // context may reclaim at all, is re-walk the zonelist against the min
        // watermark. How far into the reserve that attempt may reach is the
        // caller's to ask for: the discount comes from the high-priority flag,
        // and being unable to block deepens it only for a caller that already
        // holds one.
        let allowed = crate::oom_entry::context_allows_slowpath();
        let wmark = crate::zone::slowpath_wmark(crate::zone::grants_min_reserve(gfp), allowed);
        if let Ok(pfn) = self.alloc_inner_zoned(order, hi, wmark, mt) { return Ok(pfn); }
        match crate::oom_entry::run_slowpath(order.0, allowed,
            || self.alloc_inner_zoned(order, hi, wmark, mt).ok(),
            crate::oom_entry::reclaim_once,
            crate::oom_entry::invoke_oom)
        {
            Some(pfn) => Ok(pfn),
            None => Err(Error::NoMem),
        }
    }

    /// Walk the fallback order from the highest permitted zone downward and
    /// take the first block a zone can give up without crossing its
    /// watermark. Every zone reached is at or below `hi`, which is what makes
    /// the address bound of a constrained request unconditional.
    fn alloc_inner_zoned(&self, order: Order, hi: usize, wmark: AllocWmark, mt: MigrateType) -> KResult<Pfn> {
        if order.0 > MAX_ORDER { return Err(Error::InvalidOrder); }
        let o = order.0;
        if o == 0 {
            if let Some(pfn) = self.alloc_from_pcp(hi, wmark, mt) {
                self.zero_allocation(pfn, o);
                return Ok(Pfn(pfn));
            }
        }

        // A PCP page is deliberately absent from the mergeable lists. A
        // global miss drains eligible pagesets once before reporting no
        // memory, so cached pages cannot strand a higher-order allocation.
        let mut drained = false;
        loop {
            let taken = {
                let mut g = self.inner.lock_irqsave::<I>();
                let mut taken: Option<(u64, usize)> = None;
                let mut pos = 0usize;
                while let Some(zi) = g.zonelist.entry(pos) {
                    pos += 1;
                    if zi > hi { continue; }
                    let Some(zone) = ZoneType::from_index(zi) else { continue };
                    let mark = match wmark { AllocWmark::Low => g.wmark[zi].low, _ => g.wmark[zi].min };
                    let mut area = g.free_area(zi);
                    if o == 0 {
                        area[0] = area[0].saturating_add(self.pcp_free[zi].load(Ordering::Acquire));
                    }
                    if !zone_watermark_ok(zone, o, mark, wmark, &g.reserve, hi, &area) { continue; }
                    // SAFETY: the buddy lock is held and `zi` came from the zonelist.
                    if let Some(pfn) = unsafe { g.take_block(&self.backing, zi, o, mt) } {
                        taken = Some((pfn, zi));
                        break;
                    }
                }
                if let Some((pfn, zi)) = taken {
                    // SAFETY: pfn is the popped (and possibly split-down)
                    // free block head; verify it before releasing the lock.
                    unsafe { g.verify_poison(&self.backing, pfn) };
                    let pages = 1u64 << o;
                    g.allocated += pages;
                    g.alloc_events += 1;
                    g.alloc_event_pages += pages;
                    Some((pfn, zi))
                } else {
                    None
                }
            };
            if let Some((pfn, zi)) = taken {
                self.zone_free[zi].fetch_sub(1u64 << o, Ordering::AcqRel);
                self.zero_allocation(pfn, o);
                return Ok(Pfn(pfn));
            }
            if drained || !self.drain_pcp_below(hi) { return Err(Error::NoMem); }
            drained = true;
        }
    }

    /// Zero one block after its allocator ownership transition. Backing is
    /// held outside both lock domains, so no page write occurs under a buddy
    /// or pageset lock.
    fn zero_allocation(&self, pfn: u64, order: u8) {
        let span = 1u64 << order;
        for k in 0..span {
            // SAFETY: pfn..pfn+span is the just-allocated block, owned
            // by the caller; backing.page_ptr is pure ptr arithmetic.
            let p = unsafe { self.backing.page_ptr(Pfn(pfn + k)) };
            // The setup allocator poisons order-0 frees before `free` stamps
            // its intrusive header. Inspect the preserved body now: the zero
            // below is the first allocator write that would erase evidence of
            // a stale write while the page was free.
            #[cfg(feature = "debug-watchdog")]
            // SAFETY: p names the just-allocated, still-unzeroed page.
            unsafe {
                super::poison::report_watchdog_mismatch(
                    p,
                    (pfn + k) * PAGE_SIZE_BYTES,
                )
            };
            #[cfg(feature = "debug-cow")]
            // SAFETY: same ownership and bounds as the watchdog scan above.
            unsafe {
                super::poison::report_cow_mismatch(
                    p,
                    (pfn + k) * PAGE_SIZE_BYTES,
                )
            };
            // SAFETY: pointer is page-aligned and points to PAGE_SIZE_BYTES
            // of caller-owned memory; no aliasing for the duration.
            hal::zerotrap::trap((p) as *const u8, (PAGE_SIZE_BYTES as usize) as usize);
            // SAFETY: `p` is the HHDM address of a page this call just removed
            // from the free lists, so the allocator owns the whole
            // PAGE_SIZE_BYTES span exclusively and no other CPU can hold a
            // reference to it until the Pfn is returned to the caller.
            unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE_BYTES as usize) };
        }
    }

    /// Total free pages across global buddy areas and per-CPU pagesets.
    /// # C: O(NR_ZONES)
    pub fn free_pages(&self) -> u64 {
        let mut sum = 0u64;
        for zi in 0..NR_ZONES { sum += self.zone_free[zi].load(Ordering::Acquire); }
        sum
    }

    /// Per-order free-block counts (`free_count[o]` = number of free
    /// order-`o` blocks). For `/proc/buddyinfo` (Linux `frag_show`).
    /// Read-only snapshot under the buddy lock.
    /// # C: O(ORDERS)
    pub fn free_orders(&self) -> [u64; ORDERS] {
        let g = self.inner.lock_irqsave::<I>();
        let mut out = [0u64; ORDERS];
        for zi in 0..NR_ZONES { for mt in 0..MIGRATE_TYPES { for o in 0..ORDERS { out[o] += g.free_count[zi][mt][o]; } } }
        out
    }

    /// Total allocated pages.
    /// # C: O(1)
    pub fn allocated_pages(&self) -> u64 {
        let g = self.inner.lock_irqsave::<I>();
        let mut cached = 0u64;
        for zi in 0..NR_ZONES { cached += self.pcp_free[zi].load(Ordering::Acquire); }
        g.allocated.saturating_sub(cached)
    }

    /// Total pfn span the PMM owns (`pfn_max`).
    /// # C: O(1)
    pub fn pfn_max(&self) -> u64 {
        self.pfn_max
    }

    #[cfg(test)]
    pub(crate) fn pageblock_migratetype(&self, pfn: Pfn) -> MigrateType { self.pageblocks.get(pfn.0) }

    /// Snapshot buddy ownership and successful allocation/free events under
    /// one Buddy critical section. # C: O(MAX_ORDER); # Lk: Buddy
    pub fn snapshot(&self) -> PmmSnapshot {
        let g = self.inner.lock_irqsave::<I>();
        let mut free_pages = 0u64;
        let mut cached = 0u64;
        for zi in 0..NR_ZONES {
            free_pages += self.zone_free[zi].load(Ordering::Acquire);
            cached += self.pcp_free[zi].load(Ordering::Acquire);
        }
        PmmSnapshot {
            managed_pages: g.initial_free,
            free_pages,
            allocated_pages: g.allocated.saturating_sub(cached).saturating_sub(g.reserved),
            reserved_pages: g.reserved,
            alloc_events: g.alloc_events + self.pcp_alloc_events.load(Ordering::Acquire),
            alloc_event_pages: g.alloc_event_pages + self.pcp_alloc_event_pages.load(Ordering::Acquire),
            free_events: g.free_events + self.pcp_free_events.load(Ordering::Acquire),
            free_event_pages: g.free_event_pages + self.pcp_free_event_pages.load(Ordering::Acquire),
        }
    }

    /// Page-aligned pointer to `pfn`. **Lock-free** — backing is stored
    /// outside the Buddy spinlock so callers at higher rank (slab at
    /// rank Slab=10) can invoke without violating `06§3.6`.
    ///
    /// # SAFETY: caller holds the page (no aliasing); pfn in-range.
    /// # C: O(1)
    pub unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8 {
        // SAFETY: backing.page_ptr is pure pointer arithmetic; pfn is
        // caller-owned per fn contract.
        unsafe { self.backing.page_ptr(pfn) }
    }

}
