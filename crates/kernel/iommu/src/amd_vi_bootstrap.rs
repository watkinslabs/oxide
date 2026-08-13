use alloc::vec::Vec;
use crate::{AmdViDomain, AmdViIrTable, AmdViRegisters, AmdViTables, AmdViUnit, Mapping};
use pci::Bdf;

/// Boot-owned AMD-Vi unit state; domains are attached before translation may enable.
pub struct AmdViBootstrap { unit: AmdViUnit, regs: AmdViRegisters, tables: AmdViTables, hhdm_offset: u64, irq_tables: Vec<AmdViIrTable> }
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
        let mode = crate::AmdViIrMode::from_extended_features(regs.read64(crate::EXT_FEATURES)?);
        let mut unit = AmdViUnit::new(mmio_pa, segment, mode);
        if !unit.mapped() || !unit.quiesce_firmware(&regs) {
            // SAFETY: table-register programming was not attempted, so all
            // allocations remain private to this constructor.
            unsafe { tables.release_unpublished(); }
            return None;
        }
        // A failed register-programming sequence may already have exposed one
        // table base to hardware. Keep these allocations pinned instead of
        // freeing a potentially hardware-visible DMA span.
        if !unit.program_tables(&regs, &tables) { return None; }
        Some(Self { unit, regs, tables, hhdm_offset, irq_tables: Vec::new() })
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
    /// Drain every AMD-Vi event currently produced by this hardware unit. # C: O(events)
    pub fn drain_events(&self, visitor: &mut impl FnMut(crate::AmdViEvent)) -> bool { self.tables.drain_events(&self.regs, self.hhdm_offset, visitor) }
    /// Invalidate one changed DMA interval and wait until the command engine consumed it. # C: O(poll limit)
    pub fn invalidate_mapping(&mut self, map: Mapping, domain_id: u16) -> bool {
        let Some(last) = map.iova.end().checked_sub(pci::IOVA_PAGE_SIZE) else { return false; };
        // SAFETY: this enabled unit owns the serialized command ring and the supplied mapping belongs to its domain.
        (unsafe { self.unit.invalidate_iova_pages(&self.regs, &self.tables, self.hhdm_offset, domain_id, map.iova.start, last, true) })
            && unsafe { self.unit.wait_for_invalidations(&self.regs, &self.tables, self.hhdm_offset) }
    }
    /// Allocate and publish one requester-owned AMD-Vi MSI route. # C: O(tables + poll limit)
    pub fn allocate_msi(&mut self, bdf: Bdf, event_id: u32, vector: u8, destination_apic_id: u32) -> Option<u16> {
        let index = match self.irq_tables.iter().position(|table| table.requester() == bdf.raw()) {
            Some(index) => index,
            None => {
                let table = AmdViIrTable::new(bdf.raw(), self.hhdm_offset, self.unit.ir_mode())?;
                // SAFETY: this bootstrap owns the live requester's DTE and command ring.
                if !unsafe { self.unit.install_interrupt_table(&self.regs, &self.tables, self.hhdm_offset, bdf, table.pa()) } { return None; }
                self.irq_tables.push(table);
                self.irq_tables.len() - 1
            }
        };
        let irte = self.irq_tables[index].publish(event_id, vector, destination_apic_id)?;
        // SAFETY: the table write is release-published before its owning IRT cache invalidation.
        if unsafe { self.unit.invalidate_interrupt_table(&self.regs, &self.tables, self.hhdm_offset, bdf) } { Some(irte) } else { None }
    }
    /// Segment this unit owns. # C: O(1)
    pub const fn segment(&self) -> u16 { self.unit.segment }
    /// Check whether this unit can be considered for a requester. # C: O(1)
    pub const fn matches_segment(&self, bdf: Bdf) -> bool { bdf.segment == self.unit.segment }
}
