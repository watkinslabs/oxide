use alloc::vec::Vec;

use crate::{AmdViBootstrap, AmdViDomain};
use firmware::acpi::{IommuKind, IommuUnit};
use pci::Bdf;
use sync::{Devices, Spinlock};

const INITIAL_DOMAIN_ID: u16 = 1;
const IOVA_START: u64 = 0;
const IOVA_BYTES: u64 = 1u64 << 48;

/// Result of asking the AMD-Vi manager to own the scanned PCI requesters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViActivation { Bypass, Enabled, Failed }

struct AmdViBootUnit { unit: IommuUnit, bootstrap: AmdViBootstrap, domain: AmdViDomain }
static MANAGER: Spinlock<Vec<AmdViBootUnit>, Devices> = Spinlock::new(Vec::new());

/// Activate AMD-Vi for all firmware-owned requesters before driver probing.
///
/// # SAFETY
/// The caller must run before any requester can acquire PCI bus mastering.
/// # C: O(units + requesters + RAM leaves)
pub unsafe fn activate_amd_vi(requesters: &[Bdf], hhdm_offset: u64, regions: &[pmm::UsableRegion]) -> AmdViActivation {
    let mut units = Vec::new();
    for bdf in requesters {
        let Some(unit) = crate::amd_vi_unit_for_bdf(*bdf) else { continue; };
        push_unique_unit(&mut units, unit);
    }
    if units.is_empty() { return AmdViActivation::Bypass; }
    if units.iter().any(|unit| unit.kind != IommuKind::AmdVi) { return AmdViActivation::Failed; }

    let mut manager = Vec::new();
    for unit in units {
        let Some(mut domain) = AmdViDomain::new(IOVA_START, IOVA_BYTES, hhdm_offset) else { return AmdViActivation::Failed; };
        if !domain.map_identity_regions(regions) { return AmdViActivation::Failed; }
        // SAFETY: the firmware inventory owns this unit and PCI probing has not enabled DMA.
        let Some(bootstrap) = (unsafe { AmdViBootstrap::new(unit.register_base, unit.segment, hhdm_offset) }) else { return AmdViActivation::Failed; };
        manager.push(AmdViBootUnit { unit, bootstrap, domain });
    }

    for bdf in requesters {
        let Some(unit) = crate::amd_vi_unit_for_bdf(*bdf) else { continue; };
        let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return AmdViActivation::Failed; };
        // SAFETY: the identity domain maps every PMM-owned DMA address before translation enables.
        if !unsafe { entry.bootstrap.attach(*bdf, &entry.domain, INITIAL_DOMAIN_ID) } { return AmdViActivation::Failed; }
    }
    for entry in manager.iter_mut() {
        if !entry.bootstrap.enable() { return AmdViActivation::Failed; }
    }

    *MANAGER.lock() = manager;
    AmdViActivation::Enabled
}

/// Return whether this manager owns the full PCI requester identity. # C: O(units)
pub fn owns(requester: Bdf) -> bool {
    let Some(unit) = crate::amd_vi_unit_for_bdf(requester) else { return false; };
    MANAGER.lock().iter().any(|entry| entry.unit == unit)
}

/// Install one live AMD-Vi mapping and complete its IOTLB invalidation. # C: O(pages * levels + poll limit)
pub fn map_dma(requester: Bdf, pa: u64, len: usize) -> Option<u64> {
    let unit = crate::amd_vi_unit_for_bdf(requester)?;
    let (base, bytes, offset) = crate::dma_span::normalize_dma_span(pa, len)?;
    let mut manager = MANAGER.lock();
    let entry = manager.iter_mut().find(|entry| entry.unit == unit)?;
    let map = entry.domain.map(base, bytes, pci::IOVA_PAGE_SIZE)?;
    if !entry.bootstrap.invalidate_mapping(map, INITIAL_DOMAIN_ID) { return None; }
    map.iova.start.checked_add(offset)
}

/// Remove one exact live AMD-Vi mapping after the IOTLB has consumed the removal. # C: O(pages * levels + poll limit)
pub fn unmap_dma(requester: Bdf, iova: u64, len: usize) -> bool {
    let Some(unit) = crate::amd_vi_unit_for_bdf(requester) else { return false; };
    let page = pci::IOVA_PAGE_SIZE; let base = iova & !(page - 1); let offset = iova - base;
    let Some(bytes) = offset.checked_add(len as u64).and_then(|n| n.checked_add(page - 1)).map(|n| n & !(page - 1)) else { return false; };
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return false; };
    let Some(map) = entry.domain.mapping(base) else { return false; };
    if map.iova.len != bytes || !entry.domain.remove_for_invalidate(map) { return false; }
    entry.bootstrap.invalidate_mapping(map, INITIAL_DOMAIN_ID) && entry.domain.release_after_invalidate(map)
}

fn push_unique_unit(units: &mut Vec<IommuUnit>, unit: IommuUnit) {
    if !units.iter().any(|current| *current == unit) { units.push(unit); }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn deduplicates_requesters_but_never_crosses_a_segment_boundary() {
        let first = IommuUnit { kind: IommuKind::AmdVi, segment: 1, register_base: 0xfed8_0000, register_pages: 1, include_all: false };
        let other_segment = IommuUnit { segment: 2, ..first };
        let mut units = Vec::new();
        push_unique_unit(&mut units, first);
        push_unique_unit(&mut units, first);
        push_unique_unit(&mut units, other_segment);
        assert_eq!(units, alloc::vec![first, other_segment]);
    }
}
