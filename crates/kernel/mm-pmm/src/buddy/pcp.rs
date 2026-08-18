//! Per-CPU, per-zone order-0 pagesets.
//!
//! A pageset owns pages that are free but deliberately absent from the
//! mergeable buddy lists. Its intrusive list lives in the same free-node
//! header as a buddy block; only order-0 pages enter it. Refill and drain
//! transfer complete lists through the global allocator, so the one place
//! that splits and coalesces blocks remains `PmmInner`.

use super::*;
use super::free_node::{read_u64, write_u64, write_u8, OFF_NEXT, OFF_ORDER, OFF_POISON, OFF_PREV};
use core::sync::atomic::{AtomicU64, Ordering};

pub(super) const PCP_SLOTS: usize = cpu::MAX_CPUS * NR_ZONES;

/// Lock-free policy inputs copied from the zone owner. The list itself is
/// protected by its pageset lock; these values intentionally tolerate a
/// concurrent watermark refresh in the same way the global gate tolerates
/// concurrent page-state accounting.
pub(super) struct PcpZoneConfig {
    pub(super) low: AtomicU64,
    pub(super) min: AtomicU64,
    pub(super) reserve: [AtomicU64; NR_ZONES],
    pub(super) batch: AtomicU64,
}

impl PcpZoneConfig {
    pub(super) fn new(wmark: ZoneWatermarks, reserve: [u64; NR_ZONES], managed: u64) -> Self {
        let batch = batch_pages(managed);
        Self {
            low: AtomicU64::new(wmark.low),
            min: AtomicU64::new(wmark.min),
            reserve: core::array::from_fn(|i| AtomicU64::new(reserve[i])),
            batch: AtomicU64::new(batch),
        }
    }

    pub(super) fn refresh(&self, wmark: ZoneWatermarks, reserve: [u64; NR_ZONES], managed: u64) {
        let batch = batch_pages(managed);
        self.low.store(wmark.low, Ordering::Release);
        self.min.store(wmark.min, Ordering::Release);
        for (i, cell) in self.reserve.iter().enumerate() {
            cell.store(reserve[i], Ordering::Release);
        }
        self.batch.store(batch, Ordering::Release);
    }

    pub(super) fn mark(&self, wmark: AllocWmark) -> u64 {
        match wmark {
            AllocWmark::Low => self.low.load(Ordering::Acquire),
            _ => self.min.load(Ordering::Acquire),
        }
    }

    pub(super) fn reserve_for(&self, highest_zoneidx: usize) -> u64 {
        self.reserve[highest_zoneidx.min(NR_ZONES - 1)].load(Ordering::Acquire)
    }

    /// CPU online/offline changes do not need a PMM-wide rewrite: the next
    /// free reads the current online count while applying this zone's high
    /// mark, as the pageset policy requires.
    pub(super) fn high(&self) -> u64 {
        high_pages(
            self.low.load(Ordering::Acquire),
            self.batch.load(Ordering::Acquire).max(1),
        )
    }
}

/// Number of pages refilled from the buddy lists at once. The clamp and the
/// non-power-of-two result prevent one CPU from hoarding a large zone while
/// avoiding cache-colour aliasing from repeated power-of-two batches.
pub(super) fn batch_pages(managed: u64) -> u64 {
    let batch = (managed >> 12).min((256 * 1024) / PAGE_SIZE_BYTES);
    if batch <= 1 { return 1; }
    let scaled = batch.saturating_add(batch / 2);
    let power = 1u64 << (u64::BITS - 1 - scaled.leading_zeros());
    power.saturating_sub(1).max(1)
}

/// A zone's PCP high mark is its low watermark split over online CPUs, with
/// enough room for four refills so a short allocation/free burst stays local.
pub(super) fn high_pages(low: u64, batch: u64) -> u64 {
    let online = (cpu::smp::online_count() as u64).max(1);
    (low / online).max(batch.saturating_mul(4))
}

/// One intrusive list. It is always manipulated while its enclosing pageset
/// spinlock is held. `count` is base pages, not blocks.
pub(super) struct PcpList {
    head: u64,
    count: u64,
}

impl PcpList {
    pub(super) const fn empty() -> Self { Self { head: PFN_NULL, count: 0 } }

    pub(super) const fn head(&self) -> u64 { self.head }

    pub(super) const fn count(&self) -> u64 { self.count }

    /// # SAFETY: caller holds this list's pageset lock; `pfn` is an owned,
    /// order-0 page and has already been recorded in the PCP bitmap.
    pub(super) unsafe fn push<B: PageBacking>(&mut self, backing: &B, pfn: u64) {
        // SAFETY: pfn names the caller-owned page whose header this list owns.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: stamp the complete FreeNode layout before publishing pfn.
        unsafe {
            write_u64(page, OFF_POISON, POISON_MAGIC);
            write_u8(page, OFF_ORDER, 0);
            for i in 1..8 { write_u8(page, OFF_ORDER + i, 0); }
            write_u64(page, OFF_NEXT, self.head);
            write_u64(page, OFF_PREV, PFN_NULL);
        }
        self.head = pfn;
        self.count += 1;
    }

    /// # SAFETY: caller holds this list's pageset lock and the list's nodes
    /// belong to `backing`.
    pub(super) unsafe fn pop<B: PageBacking>(&mut self, backing: &B, pfn_max: u64) -> Option<u64> {
        if self.count == 0 { return None; }
        let pfn = self.head;
        kassert!(pfn < pfn_max, "pmm pcp head out of range");
        // SAFETY: pfn is the current PCP head while the list lock is held.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: read the stable intrusive header before unlinking it.
        let next = unsafe { read_u64(page, OFF_NEXT) };
        kassert!(next == PFN_NULL || next < pfn_max, "pmm pcp next out of range");
        kassert!(next != pfn, "pmm pcp self link");
        self.head = next;
        self.count -= 1;
        Some(pfn)
    }

    /// Detach up to `limit` pages from the list without allocating an array.
    /// # SAFETY: caller holds the pageset lock; nodes belong to `backing`.
    pub(super) unsafe fn take<B: PageBacking>(&mut self, backing: &B, pfn_max: u64, limit: u64) -> Self {
        let wanted = self.count.min(limit);
        if wanted == 0 { return Self::empty(); }
        let mut out = Self::empty();
        for _ in 0..wanted {
            // SAFETY: wanted never exceeds the current count.
            let pfn = unsafe { self.pop(backing, pfn_max) }.expect("pcp count/head mismatch");
            // SAFETY: pfn was removed from this list and is now owned by out.
            unsafe { out.push(backing, pfn) };
        }
        out
    }

    /// Move every page from `from` onto this list. # SAFETY: both lists are
    /// exclusively held and all nodes belong to `backing`.
    pub(super) unsafe fn absorb<B: PageBacking>(&mut self, backing: &B, pfn_max: u64, from: &mut Self) {
        // SAFETY: `from` remains exclusively held until each head is detached.
        while let Some(pfn) = unsafe { from.pop(backing, pfn_max) } {
            // SAFETY: pfn is detached from `from` and becomes this list's head.
            unsafe { self.push(backing, pfn) };
        }
    }
}

/// Permanent backing for one pageset per logical CPU and memory zone. The
/// locks are IRQ-safe because page allocation can run in an interrupt on the
/// same CPU as a task free. A [`PageBacking`] supplies this storage so the live
/// PMM does not materialize its complete per-CPU table on the boot stack.
pub struct PcpStorage {
    lists: [Spinlock<PcpList, Buddy>; PCP_SLOTS],
}

impl PcpStorage {
    /// Construct pageset storage for a hosted or otherwise dynamically owned
    /// backing. Kernel boot uses [`Self::init_in_place`] in static storage.
    /// # C: O(PCP_SLOTS)
    pub fn new() -> Self {
        Self { lists: core::array::from_fn(|_| Spinlock::new(PcpList::empty())) }
    }

    /// Initialize permanent storage without first creating its full table as
    /// a stack temporary.
    ///
    /// # SAFETY
    /// `out` names uninitialized, suitably aligned storage for one
    /// `PcpStorage`, and no reference to it may exist yet.
    /// # C: O(PCP_SLOTS)
    pub unsafe fn init_in_place(out: *mut Self) {
        for i in 0..PCP_SLOTS {
            // SAFETY: every element is written exactly once into the caller's
            // uninitialized `PcpStorage` allocation.
            unsafe {
                core::ptr::addr_of_mut!((*out).lists[i])
                    .write(Spinlock::new(PcpList::empty()));
            }
        }
    }

    pub(super) fn list(&self, cpu: usize, zone: usize) -> &Spinlock<PcpList, Buddy> {
        &self.lists[cpu.min(cpu::MAX_CPUS - 1) * NR_ZONES + zone]
    }

    pub(super) fn current(&self, zone: usize) -> &Spinlock<PcpList, Buddy> {
        self.list(current_cpu(), zone)
    }
}

/// Current logical CPU, matching the other PMM per-CPU owners. Hosted tests
/// have no architecture CPU register, so their one pageset is slot zero.
#[inline]
pub(super) fn current_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    fn pcp_word_bit(&self, pfn: u64) -> (&AtomicU64, u64) {
        let word = (pfn >> 6) as usize;
        (&self.pcp_bitmap[word], 1u64 << (pfn & 63))
    }

    fn pcp_mark(&self, pfn: u64) {
        let (word, bit) = self.pcp_word_bit(pfn);
        let was = word.fetch_or(bit, Ordering::AcqRel);
        kassert!(was & bit == 0, "pmm double free in per-cpu pageset");
    }

    fn pcp_unmark(&self, pfn: u64) {
        let (word, bit) = self.pcp_word_bit(pfn);
        let was = word.fetch_and(!bit, Ordering::AcqRel);
        kassert!(was & bit != 0, "pmm per-cpu pageset bitmap missing page");
    }

    pub(super) fn pcp_marked(&self, pfn: u64) -> bool {
        let (word, bit) = self.pcp_word_bit(pfn);
        word.load(Ordering::Acquire) & bit != 0
    }

    fn buddy_marked(&self, pfn: u64, order: u8) -> bool {
        let word = ((pfn >> order) >> 6) as usize;
        let bit = 1u64 << ((pfn >> order) & 63);
        self.buddy_bitmaps[order as usize][word].load(Ordering::Acquire) & bit != 0
    }

    fn pcp_watermark_ok(&self, zone: usize, highest_zoneidx: usize, wmark: AllocWmark) -> bool {
        let cfg = &self.pcp_zone[zone];
        crate::zone::zone_watermark_ok_pages(
            cfg.mark(wmark),
            wmark,
            cfg.reserve_for(highest_zoneidx),
            self.zone_free[zone].load(Ordering::Acquire),
        )
    }

    /// Try the current CPU's eligible lists first. On a local miss, move a
    /// bounded refill batch out of one eligible buddy zone, publish the batch
    /// to this CPU's pageset, then hand its first page to the caller.
    pub(super) fn alloc_from_pcp(&self, highest_zoneidx: usize, wmark: AllocWmark) -> Option<u64> {
        for zone in self.zonelist.walk(highest_zoneidx) {
            let zi = zone.index();
            if !self.pcp_watermark_ok(zi, highest_zoneidx, wmark) { continue; }
            if let Some(pfn) = self.pop_current_pcp(zi) { return Some(pfn); }
            if let Some(pfn) = self.refill_current_pcp(zi, highest_zoneidx, wmark) { return Some(pfn); }
        }
        None
    }

    fn pop_current_pcp(&self, zi: usize) -> Option<u64> {
        let pfn = {
            let mut pcp = self.pcp.current(zi).lock_irqsave::<I>();
            // SAFETY: pcp lock owns this list and pfn_max bounds every node.
            unsafe { pcp.pop(&self.backing, self.pfn_max) }
        }?;
        self.verify_pcp_page(pfn, zi);
        self.pcp_unmark(pfn);
        self.pcp_free[zi].fetch_sub(1, Ordering::AcqRel);
        self.zone_free[zi].fetch_sub(1, Ordering::AcqRel);
        self.pcp_alloc_events.fetch_add(1, Ordering::Relaxed);
        self.pcp_alloc_event_pages.fetch_add(1, Ordering::Relaxed);
        Some(pfn)
    }

    fn refill_current_pcp(&self, zi: usize, highest_zoneidx: usize, wmark: AllocWmark) -> Option<u64> {
        let wanted = self.pcp_zone[zi].batch.load(Ordering::Acquire).max(1);
        let mut refill = PcpList::empty();
        {
            let mut g = self.inner.lock_irqsave::<I>();
            for _ in 0..wanted {
                let mut area = g.free_count[zi];
                area[0] = area[0].saturating_add(self.pcp_free[zi].load(Ordering::Acquire));
                let mark = match wmark { AllocWmark::Low => g.wmark[zi].low, _ => g.wmark[zi].min };
                let Some(zone) = ZoneType::from_index(zi) else { break; };
                if !zone_watermark_ok(zone, 0, mark, wmark, &g.reserve, highest_zoneidx, &area) { break; }
                // SAFETY: zi names the zonelist entry being refilled and the
                // watermark check above admitted one more order-0 page.
                let Some(pfn) = (unsafe { g.take_block(&self.backing, zi, 0) }) else { break; };
                // SAFETY: pfn is the free block head just removed from the
                // global list. Validate it before reusing its header for a
                // PCP link, otherwise a refill could erase the evidence the
                // allocator is required to report.
                unsafe { g.verify_poison(&self.backing, pfn) };
                self.pcp_mark(pfn);
                // SAFETY: pfn just left the buddy lists and is now staged in
                // this invocation's private refill list.
                unsafe { refill.push(&self.backing, pfn) };
                g.allocated += 1;
            }
        }
        let refilled = refill.count();
        if refilled == 0 { return None; }
        let pfn = {
            let mut pcp = self.pcp.current(zi).lock_irqsave::<I>();
            // SAFETY: refill is private to this call; both list owners are held.
            unsafe { pcp.absorb(&self.backing, self.pfn_max, &mut refill) };
            // SAFETY: the refill was non-empty, so this pageset now is too.
            let pfn = unsafe { pcp.pop(&self.backing, self.pfn_max) }
                .expect("pcp refill lost its head");
            // Publish the list count before releasing its lock. A concurrent
            // global-miss drain acquires this same lock before detaching pages.
            self.pcp_free[zi].fetch_add(refilled - 1, Ordering::AcqRel);
            self.zone_free[zi].fetch_sub(1, Ordering::AcqRel);
            pfn
        };
        self.verify_pcp_page(pfn, zi);
        self.pcp_unmark(pfn);
        self.pcp_alloc_events.fetch_add(1, Ordering::Relaxed);
        self.pcp_alloc_event_pages.fetch_add(1, Ordering::Relaxed);
        Some(pfn)
    }

    /// Return an externally freed order-0 page to the local pageset. A cache
    /// above its high mark gives one batch back to the mergeable buddy lists.
    pub(super) fn free_to_pcp(&self, pfn: u64) {
        let zi = self.layout.index_of(pfn);
        kassert!(zi < NR_ZONES, "pmm pcp free pfn outside zone layout");
        self.pcp_mark(pfn);
        for order in 0..=MAX_ORDER {
            kassert!(!self.buddy_marked(pfn, order), "pmm double free detected by bitmap");
        }
        let high = self.pcp_zone[zi].high();
        let batch = self.pcp_zone[zi].batch.load(Ordering::Acquire).max(1);
        let drain = {
            let mut pcp = self.pcp.current(zi).lock_irqsave::<I>();
            // SAFETY: this call owns pfn and publishes it only to this list.
            unsafe { pcp.push(&self.backing, pfn) };
            let drain = if pcp.count() > high {
                // SAFETY: this list remains exclusively held for the detach.
                unsafe { pcp.take(&self.backing, self.pfn_max, batch) }
            } else {
                PcpList::empty()
            };
            // Make the count agree with the visible list before another CPU
            // can detach it. Detached pages are in this free operation's
            // private transfer list and are no longer pageset-resident.
            self.zone_free[zi].fetch_add(1, Ordering::AcqRel);
            self.pcp_free[zi].fetch_add(1, Ordering::AcqRel);
            self.pcp_free[zi].fetch_sub(drain.count(), Ordering::AcqRel);
            drain
        };
        self.pcp_free_events.fetch_add(1, Ordering::Relaxed);
        self.pcp_free_event_pages.fetch_add(1, Ordering::Relaxed);
        if drain.count() != 0 {
            self.drain_pcp_list(zi, drain);
        }
    }

    /// Drain every eligible pageset after a global allocation miss. A page
    /// cache must not make a higher-order request fail merely because its
    /// constituent pages are waiting on CPUs for a later free-side drain.
    pub(super) fn drain_pcp_below(&self, highest_zoneidx: usize) -> bool {
        let mut drained = false;
        for zone in self.zonelist.walk(highest_zoneidx) {
            let zi = zone.index();
            for cpu in 0..cpu::MAX_CPUS {
                let list = {
                    let mut pcp = self.pcp.list(cpu, zi).lock_irqsave::<I>();
                    // SAFETY: pcp lock owns every detached node.
                    unsafe { pcp.take(&self.backing, self.pfn_max, u64::MAX) }
                };
                if list.count() == 0 { continue; }
                drained = true;
                self.pcp_free[zi].fetch_sub(list.count(), Ordering::AcqRel);
                self.drain_pcp_list(zi, list);
            }
        }
        drained
    }

    fn drain_pcp_list(&self, zi: usize, mut list: PcpList) {
        let drained = list.count();
        let mut g = self.inner.lock_irqsave::<I>();
        while let Some(pfn) = {
            // SAFETY: list is private to this drain and all nodes are PMM-owned.
            unsafe { list.pop(&self.backing, self.pfn_max) }
        } {
            self.verify_pcp_page(pfn, zi);
            // SAFETY: pfn was removed from its PCP list and has not been
            // published elsewhere; the buddy lock owns the merge transition.
            unsafe { self.return_to_buddy(&mut g, pfn, 0, core::panic::Location::caller()) };
            self.pcp_unmark(pfn);
        }
        g.allocated -= drained;
    }

    fn verify_pcp_page(&self, pfn: u64, zi: usize) {
        kassert!(self.layout.index_of(pfn) == zi, "pmm pcp page in wrong zone");
        kassert!(self.pcp_marked(pfn), "pmm pcp list page absent from bitmap");
        // SAFETY: a PCP bitmap bit means this CPU cache owns the free page.
        let page = unsafe { self.backing.page_ptr(Pfn(pfn)) };
        // SAFETY: inspect the fixed FreeNode header before it becomes allocated.
        let poison = unsafe { read_u64(page, OFF_POISON) };
        // SAFETY: this remains the owned free-node header validated above.
        let order = unsafe { core::ptr::read(page.add(OFF_ORDER)) };
        kassert!(poison == POISON_MAGIC, "pmm poison mismatch on pcp alloc");
        kassert!(order == 0, "pmm pcp page has nonzero order");
    }

    #[cfg(test)]
    /// # C: O(NR_ZONES)
    pub(crate) fn pcp_cached_pages(&self) -> [u64; NR_ZONES] {
        core::array::from_fn(|zi| self.pcp_free[zi].load(Ordering::Acquire))
    }

    #[cfg(test)]
    /// # C: O(1)
    pub(crate) fn pcp_high_pages(&self, zone: ZoneType) -> u64 {
        self.pcp_zone[zone.index()].high()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_growth_is_bounded_and_non_power_of_two() {
        assert_eq!(batch_pages(0), 1);
        assert_eq!(batch_pages(16_384), 3);
        assert_eq!(batch_pages(u64::MAX), 63);
    }

    #[test]
    fn high_mark_keeps_four_refills() {
        assert_eq!(high_pages(0, 3), 12);
        assert_eq!(high_pages(11, 3), 12);
        assert_eq!(high_pages(128, 3), 128);
    }
}
