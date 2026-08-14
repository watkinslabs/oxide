use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
/// Result of allocating a PCI MSI/MSI-X message through AMD-Vi.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViMsi { Direct, Remapped { address: u64, data: u32 }, Failed }
/// Result of routing one I/O-APIC source through AMD-Vi.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViIoapic { Direct, Remapped { index: u8 }, Failed }

struct AmdViGroup { domain_id: u16, requesters: Vec<Bdf>, domain: AmdViDomain }
struct AmdViBootUnit { unit: IommuUnit, bootstrap: AmdViBootstrap, groups: Vec<AmdViGroup> }
static MANAGER: Spinlock<Vec<AmdViBootUnit>, Devices> = Spinlock::new(Vec::new());
static EVENT_RECORDS: AtomicU64 = AtomicU64::new(0);
static X2APIC_CAPABLE: AtomicBool = AtomicBool::new(false);

/// Activate AMD-Vi for all firmware-owned requesters before driver probing.
///
/// # SAFETY
/// The caller must run before any requester can acquire PCI bus mastering.
/// # C: O(units + requesters + RAM leaves)
#[inline(never)]
pub unsafe fn activate_amd_vi(requesters: &[Bdf], aliases: &pci::DmaAliases, hhdm_offset: u64, regions: &[pmm::UsableRegion]) -> AmdViActivation {
    X2APIC_CAPABLE.store(false, Ordering::Release);
    let mut units = Vec::new();
    for index in 0..firmware::acpi::iommu_unit_count() {
        let Some(unit) = firmware::acpi::iommu_unit(index) else { return AmdViActivation::Failed; };
        if unit.kind == IommuKind::AmdVi { push_unique_unit(&mut units, unit); }
    }
    if units.is_empty() { return AmdViActivation::Bypass; }
    if units.iter().any(|unit| unit.kind != IommuKind::AmdVi) { return AmdViActivation::Failed; }

    let mut manager = Vec::new();
    for unit in units {
        // SAFETY: the firmware inventory owns this unit and PCI probing has not enabled DMA.
        let Some(bootstrap) = (unsafe { AmdViBootstrap::new(unit.register_base, unit.segment, hhdm_offset) }) else { return AmdViActivation::Failed; };
        manager.push(AmdViBootUnit { unit, bootstrap, groups: Vec::new() });
    }

    for entry in manager.iter_mut() {
        let unit_requesters: Vec<Bdf> = requesters.iter().copied().filter(|bdf|
            crate::amd_vi_unit_for_bdf(*bdf) == Some(entry.unit)).collect();
        for (_, group_requesters) in requester_groups(&unit_requesters, |bdf|
            group_key(bdf, firmware::acpi::amd_vi_alias_for_requester(bdf.segment, bdf.raw()))) {
            let Some(domain_id) = u16::try_from(entry.groups.len()).ok().and_then(|n| INITIAL_DOMAIN_ID.checked_add(n)) else { return activation_failed(&mut manager); };
            let Some(mut domain) = AmdViDomain::new(IOVA_START, IOVA_BYTES, hhdm_offset) else { return activation_failed(&mut manager); };
            if !domain.map_identity_regions(regions) || !map_ivmd_regions(&mut domain, entry.unit, &group_requesters) { return activation_failed(&mut manager); }
            entry.groups.push(AmdViGroup { domain_id, requesters: group_requesters, domain });
        }
        for group in &entry.groups {
            for requester in &group.requesters {
                // SAFETY: every group mapping is complete before its DTE becomes present.
                if !unsafe { entry.bootstrap.attach(*requester, &group.domain, group.domain_id) } { return activation_failed(&mut manager); }
                for alias in aliases.for_requester(*requester) {
                    // SAFETY: the topology alias issues DMA for this completed requester domain.
                    if !unsafe { entry.bootstrap.attach_alias(alias, &group.domain, group.domain_id) } { return activation_failed(&mut manager); }
                }
            }
        }
    }
    for entry in manager.iter_mut() {
        if !entry.bootstrap.enable() { return activation_failed(&mut manager); }
    }

    let x2apic_capable = manager.iter().all(|entry| entry.bootstrap.x2apic_capable());
    *MANAGER.lock() = manager;
    X2APIC_CAPABLE.store(x2apic_capable, Ordering::Release);
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
        if domain.map_identity_with_permissions(ivmd.base, ivmd.len, ivmd.read, ivmd.write).is_none() { return false; }
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
    X2APIC_CAPABLE.store(false, Ordering::Release);
    AmdViActivation::Failed
}

/// Disable every active AMD-Vi unit when a later global IOMMU transition
/// rejects PCI driver admission.  Keep the manager and its table ownership
/// intact if any hardware disable handshake fails: forgetting that state
/// would let a later caller treat a still-live unit as bypassed.
/// # C: O(units)
pub fn deactivate_amd_vi() -> bool {
    let mut manager = MANAGER.lock();
    let mut complete = true;
    for entry in manager.iter_mut() { complete &= entry.bootstrap.disable(); }
    if !complete { return false; }
    manager.clear();
    X2APIC_CAPABLE.store(false, Ordering::Release);
    true
}

/// Return whether this manager owns the full PCI requester identity. # C: O(units)
pub fn owns(requester: Bdf) -> bool {
    MANAGER.lock().iter().any(|entry| entry.groups.iter().any(|group| group.requesters.iter().any(|candidate| *candidate == requester)))
}

pub(crate) fn active() -> bool { !MANAGER.lock().is_empty() }
/// Return whether every active AMD-Vi unit can remap to a 32-bit x2APIC destination. # C: O(1)
pub fn amd_vi_x2apic_capable() -> bool { X2APIC_CAPABLE.load(Ordering::Acquire) }
/// Drain all currently pending AMD-Vi fault and hardware events. # C: O(units + events)
pub fn poll_amd_vi_events(visitor: &mut impl FnMut(crate::AmdViEvent)) -> bool {
    let manager = MANAGER.lock(); let mut complete = true;
    for entry in manager.iter() { complete &= entry.bootstrap.drain_events(visitor); }
    complete
}

/// Enable every AMD-Vi event interrupt after PCI owns every delivery vector. # C: O(units)
pub fn enable_amd_vi_event_interrupts() -> bool {
    let manager = MANAGER.lock(); manager.iter().all(|entry| entry.bootstrap.enable_event_interrupts())
}

/// Mask every AMD-Vi event interrupt before releasing its PCI MSI binding. # C: O(units)
pub fn disable_amd_vi_event_interrupts() -> bool {
    let manager = MANAGER.lock(); manager.iter().all(|entry| entry.bootstrap.disable_event_interrupts())
}

/// Drain the event logs from the architecture PCI-MSI interrupt callback. # C: O(units + events)
pub fn handle_amd_vi_event_interrupt() {
    let mut discard = |_| { EVENT_RECORDS.fetch_add(1, Ordering::Relaxed); };
    let _ = poll_amd_vi_events(&mut discard);
}

/// Return the number of AMD-Vi event records drained by hardware interrupts. # C: O(1)
pub fn amd_vi_event_records() -> u64 { EVENT_RECORDS.load(Ordering::Acquire) }

/// Allocate one remapped MSI message for an AMD-Vi-owned requester. # C: O(tables + poll limit)
pub fn allocate_amd_vi_msi(requester: Bdf, event_id: u32, vector: u8, destination_apic_id: u32) -> AmdViMsi {
    let Some(unit) = crate::amd_vi_unit_for_bdf(requester) else { return AmdViMsi::Direct; };
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return AmdViMsi::Direct; };
    let Some(index) = entry.bootstrap.allocate_msi(requester, event_id, vector, destination_apic_id) else { return AmdViMsi::Failed; };
    AmdViMsi::Remapped { address: 0xfee0_0000, data: u32::from(index) }
}

/// Allocate an AMD-Vi I/O-APIC source route from its IVRS special-device mapping.
/// # C: O(special mappings + tables + poll limit)
pub fn allocate_amd_vi_ioapic(ioapic_id: u8, pin: u32, vector: u8, destination_apic_id: u32) -> AmdViIoapic {
    let special = (0..firmware::acpi::amd_vi_special_count()).find_map(|index| {
        firmware::acpi::amd_vi_special(index).filter(|special|
            special.kind == firmware::acpi::AMD_SPECIAL_IOAPIC && special.id == ioapic_id)
    });
    let Some(special) = special else { return AmdViIoapic::Direct; };
    let Some(unit) = firmware::acpi::iommu_unit(special.unit_index as usize) else { return AmdViIoapic::Failed; };
    if unit.kind != IommuKind::AmdVi { return AmdViIoapic::Failed; }
    let bdf = Bdf { segment: unit.segment, bus: (special.requester >> 8) as u8,
        device: ((special.requester >> 3) & 0x1f) as u8, function: (special.requester & 7) as u8 };
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return AmdViIoapic::Failed; };
    let Some(index) = entry.bootstrap.allocate_msi(bdf, pin, vector, destination_apic_id) else { return AmdViIoapic::Failed; };
    u8::try_from(index).map(|index| AmdViIoapic::Remapped { index }).unwrap_or(AmdViIoapic::Failed)
}

/// Install one live mapping constrained by the requester's inclusive DMA mask.
/// # C: O(pages * levels + poll limit)
pub fn map_dma_below(requester: Bdf, pa: u64, len: usize, mask: u64) -> Option<u64> {
    let unit = crate::amd_vi_unit_for_bdf(requester)?;
    let (base, bytes, offset) = crate::dma_span::normalize_dma_span(pa, len)?;
    let mut manager = MANAGER.lock();
    let entry = manager.iter_mut().find(|entry| entry.unit == unit)?;
    let group = entry.groups.iter_mut().find(|group| group.requesters.iter().any(|candidate| *candidate == requester))?;
    let map = group.domain.map_below(base, bytes, pci::IOVA_PAGE_SIZE, mask)?;
    if !entry.bootstrap.invalidate_mapping(map, group.domain_id) {
        if group.domain.remove_for_invalidate(map)
            && entry.bootstrap.invalidate_mapping(map, group.domain_id) {
            let _ = group.domain.release_after_invalidate(map);
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
    let Some(group) = entry.groups.iter_mut().find(|group| group.requesters.iter().any(|candidate| *candidate == requester)) else { return false; };
    let Some(map) = group.domain.mapping(base) else { return false; };
    if map.iova.len != bytes || !group.domain.remove_for_invalidate(map) { return false; }
    entry.bootstrap.invalidate_mapping(map, group.domain_id) && group.domain.release_after_invalidate(map)
}

fn push_unique_unit(units: &mut Vec<IommuUnit>, unit: IommuUnit) {
    if !units.iter().any(|current| *current == unit) { units.push(unit); }
}

fn group_key(bdf: Bdf, alias: Option<u16>) -> u16 { alias.unwrap_or(bdf.raw()) }

fn requester_groups(requesters: &[Bdf], key_for: impl Fn(Bdf) -> u16) -> Vec<(u16, Vec<Bdf>)> {
    let mut groups = Vec::new();
    for requester in requesters {
        let key = key_for(*requester);
        if groups.iter().any(|(existing, _)| *existing == key) { continue; }
        let members = requesters.iter().copied().filter(|candidate| key_for(*candidate) == key).collect();
        groups.push((key, members));
    }
    groups
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn deduplicates_requesters_but_never_crosses_a_segment_boundary() {
        let first = IommuUnit { kind: IommuKind::AmdVi, segment: 1, source_id: 0, event_msi: 0, register_base: 0xfed8_0000, register_pages: 1, include_all: false };
        let other_segment = IommuUnit { segment: 2, ..first };
        let mut units = Vec::new();
        push_unique_unit(&mut units, first);
        push_unique_unit(&mut units, first);
        push_unique_unit(&mut units, other_segment);
        assert_eq!(units, alloc::vec![first, other_segment]);
    }
    #[test] fn alias_and_canonical_requesters_select_one_group_key() {
        let canonical = Bdf { segment: 0, bus: 0x12, device: 3, function: 1 };
        let alias = Bdf { segment: 0, bus: 0x12, device: 4, function: 0 };
        assert_eq!(group_key(canonical, None), canonical.raw());
        assert_eq!(group_key(alias, Some(canonical.raw())), canonical.raw());
    }
    #[test] fn aliases_form_the_complete_group_before_domain_setup() {
        let canonical = Bdf { segment: 0, bus: 0x12, device: 3, function: 1 };
        let alias = Bdf { segment: 0, bus: 0x12, device: 4, function: 0 };
        let unrelated = Bdf { segment: 0, bus: 0x12, device: 5, function: 0 };
        let groups = requester_groups(&[alias, unrelated, canonical], |bdf| {
            if bdf == alias { canonical.raw() } else { bdf.raw() }
        });
        assert_eq!(groups, alloc::vec![(canonical.raw(), alloc::vec![alias, canonical]),
            (unrelated.raw(), alloc::vec![unrelated])]);
    }
}
