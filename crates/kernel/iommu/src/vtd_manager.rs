use alloc::vec::Vec;

use crate::{VtdQiQueue, VtdRegisters, VtdTables, intel_vtd_rmrr_count, intel_vtd_rmrr_for_bdf, intel_vtd_unit_for_bdf};
use firmware::acpi::{IommuKind, IommuUnit};
use pci::{Bdf, ConfigSpaceReader};
use sync::{Devices, Spinlock};

const INITIAL_DOMAIN_ID: u16 = 1;

/// Result of asking the VT-d manager to own the scanned PCI requesters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VtdActivation { Bypass, Enabled, Failed }

struct VtdBootUnit { unit: IommuUnit, regs: VtdRegisters, requesters: Vec<Bdf>, tables: VtdTables, qi: Option<VtdQiQueue> }
static MANAGER: Spinlock<Vec<VtdBootUnit>, Devices> = Spinlock::new(Vec::new());

/// Build, publish, invalidate, and enable one VT-d identity domain per hardware unit.
///
/// # SAFETY
/// The caller must run before any requester can acquire PCI bus mastering.
/// # C: O(units + requesters + RAM leaves)
pub unsafe fn activate_vtd<R: ConfigSpaceReader>(reader: &R, requesters: &[Bdf], hhdm_offset: u64,
    regions: &[pmm::UsableRegion]) -> VtdActivation {
    let mut units = Vec::new();
    for bdf in requesters {
        let Some(unit) = intel_vtd_unit_for_bdf(reader, *bdf) else { continue; };
        push_unique_unit(&mut units, unit);
    }
    if units.is_empty() { return VtdActivation::Bypass; }
    if units.iter().any(|unit| unit.kind != IommuKind::IntelVtd) { return VtdActivation::Failed; }

    let mut manager = Vec::new();
    for unit in units {
        let Some(regs) = (unsafe { VtdRegisters::map(unit.register_base, unit.register_pages) }) else { return VtdActivation::Failed; };
        let Some(mut tables) = VtdTables::new(hhdm_offset) else { return VtdActivation::Failed; };
        if !regs.cache_coherent() || !regs.supports_address_width(tables.address_width())
            || !tables.map_identity_regions(regions) { return VtdActivation::Failed; }
        let qi = if regs.supports_queued_invalidation() {
            let Some(queue) = VtdQiQueue::new(hhdm_offset) else { return VtdActivation::Failed; };
            if !regs.enable_queued_invalidation(&queue) { return VtdActivation::Failed; }
            Some(queue)
        } else { None };
        manager.push(VtdBootUnit { unit, regs, requesters: Vec::new(), tables, qi });
    }
    for entry in manager.iter_mut() {
        for index in 0..intel_vtd_rmrr_count() {
            let Some(rmrr) = rmrr_for_unit(reader, requesters, index, entry.unit) else { continue; };
            let Some(len) = rmrr.end.checked_sub(rmrr.base).and_then(|bytes| bytes.checked_add(1)) else { return VtdActivation::Failed; };
            if !entry.tables.map_identity_range(rmrr.base, len) { return VtdActivation::Failed; }
        }
    }
    for bdf in requesters {
        let Some(unit) = intel_vtd_unit_for_bdf(reader, *bdf) else { continue; };
        let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return VtdActivation::Failed; };
        if !entry.tables.attach(*bdf, INITIAL_DOMAIN_ID) { return VtdActivation::Failed; }
        entry.requesters.push(*bdf);
    }
    for entry in manager.iter_mut() {
        if !entry.regs.set_root_table(entry.tables.root_pa()) || !invalidate(entry)
            || !entry.regs.enable_translation() { return VtdActivation::Failed; }
    }
    *MANAGER.lock() = manager;
    VtdActivation::Enabled
}

/// Return whether this VT-d manager owns the exact PCI requester identity. # C: O(units * requesters)
pub fn owns(requester: Bdf) -> bool {
    MANAGER.lock().iter().any(|entry| entry.requesters.iter().any(|candidate| *candidate == requester))
}

/// Install one live mapping constrained by the requester's inclusive DMA mask.
/// # C: O(pages * levels + poll limit)
pub fn map_dma_below(requester: Bdf, pa: u64, len: usize, mask: u64) -> Option<u64> {
    let (base, bytes, offset) = crate::dma_span::normalize_dma_span(pa, len)?;
    let mut manager = MANAGER.lock();
    let entry = manager.iter_mut().find(|entry| entry.requesters.iter().any(|candidate| *candidate == requester))?;
    let map = entry.tables.map_dma_below(base, bytes, pci::IOVA_PAGE_SIZE, mask)?;
    if !invalidate(entry) { return None; }
    map.iova.start.checked_add(offset)
}

/// Remove one exact VT-d mapping only after the IOTLB has consumed its removal. # C: O(pages * levels + poll limit)
pub fn unmap_dma(requester: Bdf, iova: u64, len: usize) -> bool {
    let page = pci::IOVA_PAGE_SIZE;
    let base = iova & !(page - 1);
    let offset = iova - base;
    let Some(bytes) = offset.checked_add(len as u64).and_then(|n| n.checked_add(page - 1)).map(|n| n & !(page - 1)) else { return false; };
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.requesters.iter().any(|candidate| *candidate == requester)) else { return false; };
    let Some(map) = entry.tables.mapping(base) else { return false; };
    if map.iova.len != bytes || !entry.tables.remove_for_invalidate(map) { return false; }
    invalidate(entry) && entry.tables.release_after_invalidate(map)
}

/// Prefer capability-enabled queued invalidation; old units retain the legacy
/// register invalidation path Linux also supports. # C: O(poll limit)
fn invalidate(entry: &mut VtdBootUnit) -> bool {
    match entry.qi.as_mut() {
        Some(queue) => entry.regs.invalidate_queued(queue),
        None => entry.regs.invalidate_live_mapping(),
    }
}

fn push_unique_unit(units: &mut Vec<IommuUnit>, unit: IommuUnit) {
    if !units.iter().any(|current| *current == unit) { units.push(unit); }
}

fn rmrr_for_unit<R: ConfigSpaceReader>(reader: &R, requesters: &[Bdf], index: usize, unit: IommuUnit) -> Option<firmware::acpi::DmarRmrr> {
    requesters.iter().find_map(|bdf| {
        let rmrr = intel_vtd_rmrr_for_bdf(reader, *bdf, index)?;
        (intel_vtd_unit_for_bdf(reader, *bdf) == Some(unit)).then_some(rmrr)
    })
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn deduplicates_vtd_units_without_merging_segments() {
        let first = IommuUnit { kind: IommuKind::IntelVtd, segment: 1, register_base: 0xfed9_0000, register_pages: 1, include_all: false };
        let second = IommuUnit { segment: 2, ..first };
        let mut units = Vec::new();
        push_unique_unit(&mut units, first);
        push_unique_unit(&mut units, first);
        push_unique_unit(&mut units, second);
        assert_eq!(units, alloc::vec![first, second]);
    }
}
