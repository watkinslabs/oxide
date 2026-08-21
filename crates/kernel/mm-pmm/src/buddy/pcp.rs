//! Per-CPU, per-zone, per-migratetype order-0 pagesets.

use super::*;
use super::free_node::{read_u64, write_u64, write_u8, OFF_NEXT, OFF_ORDER, OFF_POISON, OFF_PREV};
use core::sync::atomic::{AtomicU64, Ordering};

pub(super) const PCP_SLOTS: usize = cpu::MAX_CPUS * NR_ZONES * MIGRATE_TYPES;

pub(super) struct PcpZoneConfig {
    pub(super) low: AtomicU64,
    pub(super) min: AtomicU64,
    pub(super) reserve: [AtomicU64; NR_ZONES],
    pub(super) batch: AtomicU64,
}

impl PcpZoneConfig {
    pub(super) fn new(wmark: ZoneWatermarks, reserve: [u64; NR_ZONES], managed: u64) -> Self {
        Self {
            low: AtomicU64::new(wmark.low), min: AtomicU64::new(wmark.min),
            reserve: core::array::from_fn(|i| AtomicU64::new(reserve[i])), batch: AtomicU64::new(batch_pages(managed)),
        }
    }

    pub(super) fn refresh(&self, wmark: ZoneWatermarks, reserve: [u64; NR_ZONES], managed: u64) {
        self.low.store(wmark.low, Ordering::Release); self.min.store(wmark.min, Ordering::Release);
        for (i, cell) in self.reserve.iter().enumerate() { cell.store(reserve[i], Ordering::Release); }
        self.batch.store(batch_pages(managed), Ordering::Release);
    }

    pub(super) fn mark(&self, wmark: AllocWmark) -> u64 { match wmark { AllocWmark::Low => self.low.load(Ordering::Acquire), _ => self.min.load(Ordering::Acquire) } }
    pub(super) fn reserve_for(&self, highest: usize) -> u64 { self.reserve[highest.min(NR_ZONES - 1)].load(Ordering::Acquire) }
    pub(super) fn high(&self) -> u64 { high_pages(self.low.load(Ordering::Acquire), self.batch.load(Ordering::Acquire).max(1)) }
}

pub(super) fn batch_pages(managed: u64) -> u64 {
    let batch = (managed >> 12).min((256 * 1024) / PAGE_SIZE_BYTES);
    if batch <= 1 { return 1; }
    let scaled = batch.saturating_add(batch / 2);
    (1u64 << (u64::BITS - 1 - scaled.leading_zeros())).saturating_sub(1).max(1)
}

pub(super) fn high_pages(low: u64, batch: u64) -> u64 {
    (low / (cpu::smp::online_count() as u64).max(1)).max(batch.saturating_mul(4))
}

pub(super) struct PcpList { head: u64, count: u64 }

impl PcpList {
    pub(super) const fn empty() -> Self { Self { head: PFN_NULL, count: 0 } }
    pub(super) const fn head(&self) -> u64 { self.head }
    pub(super) const fn count(&self) -> u64 { self.count }

    /// # SAFETY: caller holds the enclosing list lock and owns `pfn`.
    pub(super) unsafe fn push<B: PageBacking>(&mut self, backing: &B, pfn: u64) {
        // SAFETY: caller owns the complete order-0 page.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: stamp the stable intrusive header before publishing pfn.
        unsafe {
            write_u64(page, OFF_POISON, POISON_MAGIC); write_u8(page, OFF_ORDER, 0);
            for i in 1..8 { write_u8(page, OFF_ORDER + i, 0); }
            write_u64(page, OFF_NEXT, self.head); write_u64(page, OFF_PREV, PFN_NULL);
        }
        self.head = pfn; self.count += 1;
    }

    /// # SAFETY: caller holds the enclosing list lock.
    pub(super) unsafe fn pop<B: PageBacking>(&mut self, backing: &B, pfn_max: u64) -> Option<u64> {
        if self.count == 0 { return None; }
        let pfn = self.head;
        kassert!(pfn < pfn_max, "pmm pcp head out of range");
        // SAFETY: pfn is the list head while its lock is held.
        let page = unsafe { backing.page_ptr(Pfn(pfn)) };
        // SAFETY: read pfn's current intrusive next link.
        let next = unsafe { read_u64(page, OFF_NEXT) };
        kassert!(next == PFN_NULL || next < pfn_max, "pmm pcp next out of range");
        kassert!(next != pfn, "pmm pcp self link");
        self.head = next; self.count -= 1; Some(pfn)
    }

    /// # SAFETY: caller holds the enclosing list lock.
    pub(super) unsafe fn take<B: PageBacking>(&mut self, backing: &B, pfn_max: u64, limit: u64) -> Self {
        let mut out = Self::empty();
        for _ in 0..self.count.min(limit) {
            // SAFETY: the loop bound is no greater than the original count.
            let pfn = unsafe { self.pop(backing, pfn_max) }.expect("pcp count/head mismatch");
            // SAFETY: pfn just became private to out.
            unsafe { out.push(backing, pfn) };
        }
        out
    }

}

/// Permanent pageset storage. Each mobility class has its own cache so a
/// local reuse cannot blur the allocator's free-list partition.
pub struct PcpStorage { lists: [Spinlock<PcpList, Buddy>; PCP_SLOTS] }

impl PcpStorage {
    /// # C: O(PCP_SLOTS)
    pub fn new() -> Self { Self { lists: core::array::from_fn(|_| Spinlock::new(PcpList::empty())) } }

    /// # SAFETY: `out` is unique uninitialized storage for one pageset table.
    /// # C: O(PCP_SLOTS)
    pub unsafe fn init_in_place(out: *mut Self) {
        for i in 0..PCP_SLOTS {
            // SAFETY: each element is initialized exactly once.
            unsafe { core::ptr::addr_of_mut!((*out).lists[i]).write(Spinlock::new(PcpList::empty())); }
        }
    }

    pub(super) fn list(&self, cpu: usize, zone: usize, mt: MigrateType) -> &Spinlock<PcpList, Buddy> {
        &self.lists[(cpu.min(cpu::MAX_CPUS - 1) * NR_ZONES + zone) * MIGRATE_TYPES + mt.index()]
    }
}

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
    fn with_current_pcp<R>(&self, zone: usize, mt: MigrateType,
                           f: impl FnOnce(&mut PcpList) -> R) -> R {
        // SAFETY: this outer local-IRQ pin is paired below. It must precede
        // current_cpu(): selecting first permits migration before the list
        // lock's own irqsave, violating per-CPU pageset ownership.
        let flags = unsafe { I::save_disable() };
        let cpu = current_cpu();
        let out = {
            let mut pcp = self.pcp.list(cpu, zone, mt).lock_irqsave::<I>();
            f(&mut pcp)
        };
        // SAFETY: paired with the outer save_disable after the nested list
        // guard restored the already-disabled intermediate state.
        unsafe { I::restore(flags); }
        out
    }

    fn pcp_word_bit(&self, pfn: u64) -> (&AtomicU64, u64) { (&self.pcp_bitmap[(pfn >> 6) as usize], 1u64 << (pfn & 63)) }
    fn pcp_mark(&self, pfn: u64) { let (word, bit) = self.pcp_word_bit(pfn); kassert!(word.fetch_or(bit, Ordering::AcqRel) & bit == 0, "pmm double free in per-cpu pageset"); }
    fn pcp_unmark(&self, pfn: u64) { let (word, bit) = self.pcp_word_bit(pfn); kassert!(word.fetch_and(!bit, Ordering::AcqRel) & bit != 0, "pmm per-cpu pageset bitmap missing page"); }
    pub(super) fn pcp_marked(&self, pfn: u64) -> bool { let (word, bit) = self.pcp_word_bit(pfn); word.load(Ordering::Acquire) & bit != 0 }
    fn buddy_marked(&self, pfn: u64, order: u8) -> bool { self.buddy_bitmaps[order as usize][((pfn >> order) >> 6) as usize].load(Ordering::Acquire) & (1u64 << ((pfn >> order) & 63)) != 0 }
    fn pcp_type(&self, pfn: u64) -> MigrateType { self.pageblocks.get(pfn) }

    fn pcp_watermark_ok(&self, zone: usize, highest: usize, wmark: AllocWmark) -> bool {
        let cfg = &self.pcp_zone[zone];
        crate::zone::zone_watermark_ok_pages(cfg.mark(wmark), wmark, cfg.reserve_for(highest), self.zone_free[zone].load(Ordering::Acquire))
    }

    pub(super) fn alloc_from_pcp(&self, highest: usize, wmark: AllocWmark, mt: MigrateType) -> Option<u64> {
        for zone in self.zonelist.walk(highest) {
            let zi = zone.index();
            if !self.pcp_watermark_ok(zi, highest, wmark) { continue; }
            if let Some(pfn) = self.pop_current_pcp(zi, mt) { return Some(pfn); }
            if let Some(pfn) = self.refill_current_pcp(zi, highest, wmark, mt) { return Some(pfn); }
        }
        None
    }

    fn pop_current_pcp(&self, zone: usize, mt: MigrateType) -> Option<u64> {
        let pfn = self.with_current_pcp(zone, mt, |pcp| {
            let pfn = unsafe { pcp.pop(&self.backing, self.pfn_max) }?;
            self.verify_pcp_page(pfn, zone, mt); self.pcp_unmark(pfn); Some(pfn)
        })?;
        self.pcp_free[zone].fetch_sub(1, Ordering::AcqRel); self.zone_free[zone].fetch_sub(1, Ordering::AcqRel);
        self.pcp_alloc_events.fetch_add(1, Ordering::Relaxed); self.pcp_alloc_event_pages.fetch_add(1, Ordering::Relaxed); Some(pfn)
    }

    fn refill_current_pcp(&self, zone: usize, highest: usize, wmark: AllocWmark, mt: MigrateType) -> Option<u64> {
        let wanted = self.pcp_zone[zone].batch.load(Ordering::Acquire).max(1);
        let mut refill = PcpList::empty();
        {
            let mut g = self.inner.lock_irqsave::<I>();
            for _ in 0..wanted {
                let mut area = g.free_area(zone);
                area[0] = area[0].saturating_add(self.pcp_free[zone].load(Ordering::Acquire));
                let mark = match wmark { AllocWmark::Low => g.wmark[zone].low, _ => g.wmark[zone].min };
                let Some(zone_type) = ZoneType::from_index(zone) else { break; };
                if !zone_watermark_ok(zone_type, 0, mark, wmark, &g.reserve, highest, &area) { break; }
                // SAFETY: the watermark admitted a globally free order-0 page.
                let Some(pfn) = (unsafe { g.take_block(&self.backing, zone, 0, mt) }) else { break; };
                // SAFETY: pfn just left the global free lists.
                unsafe { g.verify_poison(&self.backing, pfn) };
                // SAFETY: pfn is private to this refill staging list.
                unsafe { refill.push(&self.backing, pfn) };
                g.allocated += 1;
            }
        }
        let count = refill.count();
        if count == 0 { return None; }
        let pfn = self.with_current_pcp(zone, mt, |pcp| {
            // SAFETY: refill is a nonempty private batch from Buddy.
            let pfn = unsafe { refill.pop(&self.backing, self.pfn_max) }
                .expect("pcp refill lost its head");
            while let Some(cached) = unsafe { refill.pop(&self.backing, self.pfn_max) } {
                self.pcp_mark(cached);
                // SAFETY: cached becomes PCP-owned with its bitmap bit under
                // the same list lock that publishes the intrusive link.
                unsafe { pcp.push(&self.backing, cached) };
            }
            self.pcp_free[zone].fetch_add(count - 1, Ordering::AcqRel);
            self.zone_free[zone].fetch_sub(1, Ordering::AcqRel); pfn
        });
        self.verify_pcp_node(pfn, zone, mt);
        self.pcp_alloc_events.fetch_add(1, Ordering::Relaxed); self.pcp_alloc_event_pages.fetch_add(1, Ordering::Relaxed); Some(pfn)
    }

    pub(super) fn free_to_pcp(&self, pfn: u64) {
        let zone = self.layout.index_of(pfn); let mt = self.pcp_type(pfn);
        kassert!(zone < NR_ZONES, "pmm pcp free pfn outside zone layout");
        for order in 0..=MAX_ORDER { kassert!(!self.buddy_marked(pfn, order), "pmm double free detected by bitmap"); }
        let high = self.pcp_zone[zone].high(); let batch = self.pcp_zone[zone].batch.load(Ordering::Acquire).max(1);
        let drain = self.with_current_pcp(zone, mt, |pcp| {
            self.pcp_mark(pfn);
            // SAFETY: caller owns pfn and the selected type list is held.
            unsafe { pcp.push(&self.backing, pfn) };
            let drain = if pcp.count() > high {
                let list = unsafe { pcp.take(&self.backing, self.pfn_max, batch) };
                self.release_pcp_batch(zone, mt, list)
            } else { PcpList::empty() };
            self.zone_free[zone].fetch_add(1, Ordering::AcqRel);
            self.pcp_free[zone].fetch_add(1, Ordering::AcqRel);
            self.pcp_free[zone].fetch_sub(drain.count(), Ordering::AcqRel); drain
        });
        self.pcp_free_events.fetch_add(1, Ordering::Relaxed); self.pcp_free_event_pages.fetch_add(1, Ordering::Relaxed);
        if drain.count() != 0 { self.drain_pcp_list(zone, mt, drain); }
    }

    pub(super) fn drain_pcp_below(&self, highest: usize) -> bool {
        let mut drained = false;
        for zone in self.zonelist.walk(highest) {
            let zi = zone.index();
            for mt_index in 0..MIGRATE_TYPES { for cpu in 0..cpu::MAX_CPUS {
                let mt = MigrateType::from_index(mt_index);
                let list = {
                    let mut pcp = self.pcp.list(cpu, zi, mt).lock_irqsave::<I>();
                    let list = unsafe { pcp.take(&self.backing, self.pfn_max, u64::MAX) };
                    self.release_pcp_batch(zi, mt, list)
                };
                if list.count() == 0 { continue; }
                drained = true; self.pcp_free[zi].fetch_sub(list.count(), Ordering::AcqRel); self.drain_pcp_list(zi, mt, list);
            }}
        }
        drained
    }

    fn drain_pcp_list(&self, zone: usize, mt: MigrateType, mut list: PcpList) {
        let drained = list.count(); let mut g = self.inner.lock_irqsave::<I>();
        while let Some(pfn) = unsafe { list.pop(&self.backing, self.pfn_max) } {
            self.verify_pcp_node(pfn, zone, mt);
            // SAFETY: pfn is detached and Buddy owns the global transition.
            unsafe { self.return_to_buddy(&mut g, pfn, 0, core::panic::Location::caller()) };
        }
        g.allocated -= drained;
    }

    /// Remove bitmap ownership from a just-detached batch while the source
    /// PCP lock still excludes every list publisher. The returned intrusive
    /// list is private staging and may subsequently enter Buddy without an
    /// interval in which both owners claim the PFN.
    fn release_pcp_batch(&self, zone: usize, mt: MigrateType, mut list: PcpList) -> PcpList {
        let mut private = PcpList::empty();
        while let Some(pfn) = unsafe { list.pop(&self.backing, self.pfn_max) } {
            self.verify_pcp_page(pfn, zone, mt); self.pcp_unmark(pfn);
            // SAFETY: pfn is private after its list removal and bitmap clear.
            unsafe { private.push(&self.backing, pfn) };
        }
        private
    }

    fn verify_pcp_page(&self, pfn: u64, zone: usize, mt: MigrateType) {
        self.verify_pcp_node(pfn, zone, mt);
        kassert!(self.pcp_marked(pfn), "pmm pcp list page absent from bitmap");
    }

    fn verify_pcp_node(&self, pfn: u64, zone: usize, mt: MigrateType) {
        kassert!(self.layout.index_of(pfn) == zone, "pmm pcp page in wrong zone");
        kassert!(self.pcp_type(pfn) == mt, "pmm pcp page wrong migratetype");
        // SAFETY: PCP membership makes this free node PMM-owned.
        let page = unsafe { self.backing.page_ptr(Pfn(pfn)) };
        // SAFETY: inspect only the fixed free-node header.
        let (poison, order) = unsafe { (read_u64(page, OFF_POISON), core::ptr::read(page.add(OFF_ORDER))) };
        kassert!(poison == POISON_MAGIC, "pmm poison mismatch on pcp alloc"); kassert!(order == 0, "pmm pcp page has nonzero order");
    }

    #[cfg(test)]
    pub(crate) fn pcp_cached_pages(&self) -> [u64; NR_ZONES] { core::array::from_fn(|zone| self.pcp_free[zone].load(Ordering::Acquire)) }
    #[cfg(test)]
    pub(crate) fn pcp_high_pages(&self, zone: ZoneType) -> u64 { self.pcp_zone[zone.index()].high() }
    #[cfg(test)]
    pub(crate) fn drain_pcp_for_test(&self) { let _ = self.drain_pcp_below(NR_ZONES - 1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_growth_is_bounded_and_non_power_of_two() { assert_eq!(batch_pages(0), 1); assert_eq!(batch_pages(16_384), 3); assert_eq!(batch_pages(u64::MAX), 63); }
    #[test]
    fn high_mark_keeps_four_refills() { assert_eq!(high_pages(0, 3), 12); assert_eq!(high_pages(11, 3), 12); assert_eq!(high_pages(128, 3), 128); }
}
