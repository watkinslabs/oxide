use crate::{AmdViDomain, AmdViRegisters, AmdViTables, AmdViUnit};
use pci::Bdf;

/// Boot-owned AMD-Vi unit state; domains are attached before translation may enable.
pub struct AmdViBootstrap { unit: AmdViUnit, regs: AmdViRegisters, tables: AmdViTables, hhdm_offset: u64, next_domain: u16 }
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
        Some(Self { unit, regs, tables, hhdm_offset, next_domain: 1 })
    }
    /// Attach an already-identity-mapped requester domain and invalidate its DTE.
    ///
    /// # SAFETY
    /// `domain` must cover every DMA address the requester may issue before enable.
    /// # C: O(1)
    pub unsafe fn attach(&mut self, domain: &AmdViDomain) -> bool {
        let id = self.next_domain;
        if id == 0 { return false; }
        // SAFETY: caller guarantees the domain covers this requester's initial DMA set.
        if unsafe { !self.unit.install_initial_domain(&self.regs, &self.tables, self.hhdm_offset, domain, id) } { return false; }
        // SAFETY: the just-published DTE belongs to this bootstrap-owned command ring.
        if unsafe { !self.unit.invalidate_initial_dte(&self.regs, &self.tables, self.hhdm_offset, domain.requester()) } { return false; }
        self.next_domain = id.checked_add(1).unwrap_or(0);
        true
    }
    /// Enable translation only after every attached requester invalidation drained. # C: O(1)
    pub fn enable(&mut self) -> bool {
        self.unit.invalidations_drained(&self.regs, &self.tables)
            && self.unit.domains_attached_after_drain(&self.regs, &self.tables)
            && self.unit.enable_translation(&self.regs)
    }
    /// Segment this unit owns. # C: O(1)
    pub const fn segment(&self) -> u16 { self.unit.segment }
    /// Check whether this unit can be considered for a requester. # C: O(1)
    pub const fn matches_segment(&self, bdf: Bdf) -> bool { bdf.segment == self.unit.segment }
}
