use crate::{AmdViDomain, AmdViRegisters, AmdViTables, AmdViUnit, Mapping};
use pci::Bdf;

/// Boot-owned AMD-Vi unit state; domains are attached before translation may enable.
pub struct AmdViBootstrap { unit: AmdViUnit, regs: AmdViRegisters, tables: AmdViTables, hhdm_offset: u64 }
impl AmdViBootstrap {
    /// Map one firmware-owned unit and program its disabled translation tables.
    ///
    /// # SAFETY
    /// `mmio_pa` must name an aligned, exclusively owned firmware IOMMU aperture.
    /// # C: O(table bytes)
    pub unsafe fn new(mmio_pa: u64, segment: u16, hhdm_offset: u64) -> Option<Self> {
        // SAFETY: caller supplied one validated and exclusively owned IOMMU aperture.
        let regs = unsafe { AmdViRegisters::map(mmio_pa) }?;
        let tables = AmdViTables::allocate(hhdm_offset)?;
        let mut unit = AmdViUnit::new(mmio_pa, segment);
        if !unit.mapped() || !unit.program_tables(&regs, &tables) { return None; }
        Some(Self { unit, regs, tables, hhdm_offset })
    }
    /// Attach an already-identity-mapped domain to one requester and invalidate its DTE.
    ///
    /// # SAFETY
    /// `domain` must cover every DMA address `bdf` may issue before enable.
    /// # C: O(1)
    pub unsafe fn attach(&mut self, bdf: Bdf, domain: &AmdViDomain, domain_id: u16) -> bool {
        if domain_id == 0 { return false; }
        // SAFETY: caller guarantees the domain covers this requester's initial DMA set.
        if unsafe { !self.unit.install_initial_domain(&self.regs, &self.tables, self.hhdm_offset, bdf, domain, domain_id) } { return false; }
        // SAFETY: the just-published DTE belongs to this bootstrap-owned command ring.
        if unsafe { !self.unit.invalidate_initial_dte(&self.regs, &self.tables, self.hhdm_offset, bdf) } { return false; }
        true
    }
    /// Enable translation only after every attached requester invalidation drained. # C: O(poll limit)
    pub fn enable(&mut self) -> bool {
        // SAFETY: bootstrap owns this disabled unit and its permanent completion record.
        (unsafe { self.unit.wait_for_invalidations(&self.regs, &self.tables, self.hhdm_offset) })
            && self.unit.domains_attached_after_drain()
            && self.unit.enable_translation(&self.regs)
    }
    /// Disable every hardware feature this bootstrap enabled. # C: O(1)
    pub fn disable(&mut self) -> bool { self.unit.disable_bootstrap(&self.regs) }
    /// Invalidate one changed DMA interval and wait until the command engine consumed it. # C: O(poll limit)
    pub fn invalidate_mapping(&mut self, map: Mapping, domain_id: u16) -> bool {
        let Some(last) = map.iova.end().checked_sub(pci::IOVA_PAGE_SIZE) else { return false; };
        // SAFETY: this enabled unit owns the serialized command ring and the supplied mapping belongs to its domain.
        (unsafe { self.unit.invalidate_iova_pages(&self.regs, &self.tables, self.hhdm_offset, domain_id, map.iova.start, last, true) })
            && unsafe { self.unit.wait_for_invalidations(&self.regs, &self.tables, self.hhdm_offset) }
    }
    /// Segment this unit owns. # C: O(1)
    pub const fn segment(&self) -> u16 { self.unit.segment }
    /// Check whether this unit can be considered for a requester. # C: O(1)
    pub const fn matches_segment(&self, bdf: Bdf) -> bool { bdf.segment == self.unit.segment }
}
