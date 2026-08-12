use firmware::acpi::{DMAR_RMRR_SCOPE_UNIT, DmarRmrr, DmarScope, IommuUnit, dmar_rmrr, dmar_rmrr_count, dmar_scope, dmar_scope_count, iommu_unit, iommu_unit_count};
use pci::{Bdf, ConfigSpaceReader, PciDevice, bridge_buses};

const DMAR_SCOPE_ENDPOINT: u8 = 1;
const DMAR_SCOPE_BRIDGE: u8 = 2;
const DMAR_SCOPE_IOAPIC: u8 = 3;
const DMAR_SCOPE_HPET: u8 = 4;
const PCI_DEVICES: u8 = 32;
const PCI_FUNCTIONS: u8 = 8;

fn scope_target<R: ConfigSpaceReader>(r: &R, segment: u16, scope: DmarScope) -> Option<Bdf> {
    if scope.path_len == 0 || scope.path_len & 1 != 0 { return None; }
    let mut bus = scope.start_bus;
    let levels = scope.path_len as usize / 2;
    for level in 0..levels {
        let bdf = Bdf { segment, bus, device: scope.path[level * 2], function: scope.path[level * 2 + 1] };
        if bdf.device >= PCI_DEVICES || bdf.function >= PCI_FUNCTIONS { return None; }
        PciDevice::from_config(r, bdf)?;
        if level + 1 == levels { return Some(bdf); }
        bus = bridge_buses(r, bdf)?.secondary;
    }
    None
}

fn parent_bridge<R: ConfigSpaceReader>(r: &R, child: Bdf) -> Option<Bdf> {
    let mut best = None;
    let mut span = u16::MAX;
    for bus in 0..=u8::MAX {
        for device in 0..PCI_DEVICES {
            for function in 0..PCI_FUNCTIONS {
                let bdf = Bdf { segment: child.segment, bus, device, function };
                let Some(window) = bridge_buses(r, bdf) else { continue; };
                if child.bus < window.secondary || child.bus > window.subordinate { continue; }
                let candidate_span = u16::from(window.subordinate) - u16::from(window.secondary);
                if candidate_span < span { best = Some(bdf); span = candidate_span; }
            }
        }
    }
    best
}

fn scope_matches<R: ConfigSpaceReader>(r: &R, bdf: Bdf, scope: DmarScope, segment: u16) -> bool {
    if segment != bdf.segment { return false; }
    let Some(target) = scope_target(r, bdf.segment, scope) else { return false; };
    match scope.scope_type {
        DMAR_SCOPE_ENDPOINT => target == bdf,
        DMAR_SCOPE_BRIDGE => {
            let mut current = Some(bdf);
            for _ in 0..=u8::MAX {
                let Some(node) = current else { break; };
                if node == target { return true; }
                current = parent_bridge(r, node);
            }
            false
        }
        _ => false,
    }
}

/// Return the unique VT-d unit covering this PCI requester. # C: O(N_scopes * PCI_tree)
pub fn intel_vtd_unit_for_bdf<R: ConfigSpaceReader>(r: &R, bdf: Bdf) -> Option<IommuUnit> {
    let mut found = None;
    for index in 0..dmar_scope_count() {
        let scope = dmar_scope(index)?;
        if scope.unit_index == DMAR_RMRR_SCOPE_UNIT { continue; }
        let unit = iommu_unit(scope.unit_index as usize)?;
        if !scope_matches(r, bdf, scope, unit.segment) { continue; }
        if found.is_some_and(|old: IommuUnit| old != unit) { return None; }
        found = Some(unit);
    }
    if found.is_some() { return found; }
    for index in 0..iommu_unit_count() {
        let unit = iommu_unit(index)?;
        if unit.kind == firmware::acpi::IommuKind::IntelVtd && unit.segment == bdf.segment && unit.include_all {
            if found.is_some_and(|old: IommuUnit| old != unit) { return None; }
            found = Some(unit);
        }
    }
    found
}

/// Resolve the Intel-DMAR IOAPIC scope selected by its MADT APIC ID.  VT-d
/// interrupt remapping verifies the IOAPIC's PCI source ID, not the legacy
/// interrupt-line byte.  Ambiguous firmware ownership is refused. # C: O(N_scopes * PCI_tree)
pub fn intel_vtd_ioapic_source<R: ConfigSpaceReader>(r: &R, ioapic_id: u8) -> Option<(IommuUnit, u16)> {
    let mut found = None;
    for index in 0..dmar_scope_count() {
        let scope = dmar_scope(index)?;
        if scope.unit_index == DMAR_RMRR_SCOPE_UNIT { continue; }
        let unit = iommu_unit(scope.unit_index as usize)?;
        let Some(candidate) = ioapic_scope_source(r, ioapic_id, unit, scope) else { continue; };
        if found.is_some_and(|old| old != candidate) { return None; }
        found = Some(candidate);
    }
    found
}

fn ioapic_scope_source<R: ConfigSpaceReader>(r: &R, ioapic_id: u8, unit: IommuUnit,
    scope: DmarScope) -> Option<(IommuUnit, u16)> {
    if scope.unit_index == DMAR_RMRR_SCOPE_UNIT || scope.scope_type != DMAR_SCOPE_IOAPIC
        || scope.enumeration_id != ioapic_id || unit.kind != firmware::acpi::IommuKind::IntelVtd { return None; }
    let bdf = scope_target(r, unit.segment, scope)?;
    let source_id = (u16::from(bdf.bus) << 8) | (u16::from(bdf.device) << 3) | u16::from(bdf.function);
    Some((unit, source_id))
}

/// Resolve the Intel-DMAR HPET scope selected by the ACPI HPET block number.
/// HPET FSB interrupts must use its firmware-owned PCI source ID; ambiguous
/// firmware ownership is refused. # C: O(N_scopes * PCI_tree)
pub fn intel_vtd_hpet_source<R: ConfigSpaceReader>(r: &R, hpet_id: u8) -> Option<(IommuUnit, u16)> {
    let mut found = None;
    for index in 0..dmar_scope_count() {
        let scope = dmar_scope(index)?;
        if scope.unit_index == DMAR_RMRR_SCOPE_UNIT { continue; }
        let unit = iommu_unit(scope.unit_index as usize)?;
        let Some(candidate) = hpet_scope_source(r, hpet_id, unit, scope) else { continue; };
        if found.is_some_and(|old| old != candidate) { return None; }
        found = Some(candidate);
    }
    found
}

fn hpet_scope_source<R: ConfigSpaceReader>(r: &R, hpet_id: u8, unit: IommuUnit,
    scope: DmarScope) -> Option<(IommuUnit, u16)> {
    if scope.scope_type != DMAR_SCOPE_HPET || scope.enumeration_id != hpet_id
        || unit.kind != firmware::acpi::IommuKind::IntelVtd { return None; }
    let bdf = scope_target(r, unit.segment, scope)?;
    let source_id = (u16::from(bdf.bus) << 8) | (u16::from(bdf.device) << 3) | u16::from(bdf.function);
    Some((unit, source_id))
}

/// Return a VT-d reserved DMA range that firmware assigned to this requester. # C: O(N_scopes * PCI_tree)
pub fn intel_vtd_rmrr_for_bdf<R: ConfigSpaceReader>(r: &R, bdf: Bdf, index: usize) -> Option<DmarRmrr> {
    let rmrr = dmar_rmrr(index)?;
    rmrr_matches(r, bdf, rmrr).then_some(rmrr)
}

fn rmrr_matches<R: ConfigSpaceReader>(r: &R, bdf: Bdf, rmrr: DmarRmrr) -> bool {
    if rmrr.segment != bdf.segment { return false; }
    for scope in rmrr.scopes[..rmrr.scope_count].iter().copied() {
        if scope_matches(r, bdf, scope, rmrr.segment) { return true; }
    }
    false
}

/// Count firmware-reserved VT-d DMA ranges. # C: O(1)
pub fn intel_vtd_rmrr_count() -> usize { dmar_rmrr_count() }

#[cfg(test)] mod tests;
