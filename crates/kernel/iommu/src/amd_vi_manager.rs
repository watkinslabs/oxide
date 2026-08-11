use alloc::{boxed::Box, vec::Vec};

use crate::{AmdViBootstrap, AmdViDomain};
use firmware::acpi::{IommuKind, IommuUnit};
use pci::Bdf;

const INITIAL_DOMAIN_ID: u16 = 1;
const IOVA_START: u64 = 0;
const IOVA_BYTES: u64 = 1u64 << 48;

/// Result of asking the AMD-Vi manager to own the scanned PCI requesters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViActivation { Bypass, Enabled, Failed }

struct AmdViBootUnit { unit: IommuUnit, bootstrap: AmdViBootstrap, domain: AmdViDomain }

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

    let _ = Box::leak(Box::new(manager));
    AmdViActivation::Enabled
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
