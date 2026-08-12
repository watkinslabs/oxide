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
        if !domain.map_identity_regions(regions) || !map_ivmd_regions(&mut domain, unit, requesters) { return AmdViActivation::Failed; }
        // SAFETY: the firmware inventory owns this unit and PCI probing has not enabled DMA.
        let Some(bootstrap) = (unsafe { AmdViBootstrap::new(unit.register_base, unit.segment, hhdm_offset) }) else { return AmdViActivation::Failed; };
        manager.push(AmdViBootUnit { unit, bootstrap, domain });
    }

    for bdf in requesters {
        let Some(unit) = crate::amd_vi_unit_for_bdf(*bdf) else { continue; };
        let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return activation_failed(&mut manager); };
        // SAFETY: the identity domain maps every PMM-owned DMA address before translation enables.
        if !unsafe { entry.bootstrap.attach(*bdf, &entry.domain, INITIAL_DOMAIN_ID) } { return activation_failed(&mut manager); }
    }
    for entry in manager.iter_mut() {
        if !entry.bootstrap.enable() { return activation_failed(&mut manager); }
    }

    *MANAGER.lock() = manager;
    AmdViActivation::Enabled
}

/// Map the validated firmware ranges Linux calls IVMD unity/exclusion maps
/// before an AMD-Vi DTE may expose its page table to hardware. # C: O(IVMDs)
fn map_ivmd_regions(domain: &mut AmdViDomain, unit: IommuUnit, requesters: &[Bdf]) -> bool {
    for index in 0..firmware::acpi::amd_ivmd_count() {
        let Some(ivmd) = firmware::acpi::amd_ivmd(index) else { return false; };
        if ivmd.segment != unit.segment || !requesters.iter().any(|bdf| {
            let requester = (u16::from(bdf.bus) << 8) | (u16::from(bdf.device) << 3) | u16::from(bdf.function);
            bdf.segment == ivmd.segment && requester >= ivmd.first_requester && requester <= ivmd.last_requester
        }) { continue; }
        if domain.map_identity(ivmd.base, ivmd.len).is_none() { return false; }
    }
    true
}

/// Roll back every touched AMD-Vi unit after a global bootstrap failure.
///
/// Linux's `iommu_disable()` first stops command and event machinery and then
/// clears translation. We apply that to all units, including ones that reached
/// `Enabled` before a later unit failed. # C: O(units)
fn activation_failed(manager: &mut [AmdViBootUnit]) -> AmdViActivation {
    for entry in manager.iter_mut() { let _ = entry.bootstrap.disable(); }
    MANAGER.lock().clear();
    AmdViActivation::Failed
}

/// Return whether this manager owns the full PCI requester identity. # C: O(units)
pub fn owns(requester: Bdf) -> bool {
    let Some(unit) = crate::amd_vi_unit_for_bdf(requester) else { return false; };
    MANAGER.lock().iter().any(|entry| entry.unit == unit)
}

/// Install one live mapping constrained by the requester's inclusive DMA mask.
/// # C: O(pages * levels + poll limit)
pub fn map_dma_below(requester: Bdf, pa: u64, len: usize, mask: u64) -> Option<u64> {
    let unit = crate::amd_vi_unit_for_bdf(requester)?;
    let (base, bytes, offset) = crate::dma_span::normalize_dma_span(pa, len)?;
    let mut manager = MANAGER.lock();
    let entry = manager.iter_mut().find(|entry| entry.unit == unit)?;
    let map = entry.domain.map_below(base, bytes, pci::IOVA_PAGE_SIZE, mask)?;
    if !entry.bootstrap.invalidate_mapping(map, INITIAL_DOMAIN_ID) {
        if entry.domain.remove_for_invalidate(map)
            && entry.bootstrap.invalidate_mapping(map, INITIAL_DOMAIN_ID) {
            let _ = entry.domain.release_after_invalidate(map);
        }
        return None;
    }
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
