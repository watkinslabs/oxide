use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{VtdIrTable, VtdQiQueue, VtdRegisters, VtdTables, intel_vtd_hpet_source, intel_vtd_ioapic_source, intel_vtd_rmrr_count, intel_vtd_rmrr_for_bdf, intel_vtd_unit_for_bdf, remapped_msi};
use firmware::acpi::{IommuKind, IommuUnit};
use pci::{Bdf, ConfigSpaceReader};
use sync::{Devices, Spinlock};

const INITIAL_DOMAIN_ID: u16 = 1;

/// Result of asking the VT-d manager to own the scanned PCI requesters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VtdActivation { Bypass, Enabled, Failed }
/// Result of allocating an x86 PCI message through the VT-d IRQ owner.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VtdMsi { Direct, Remapped { address: u64, data: u32 }, Failed }
/// Result of allocating an x86 IOAPIC interrupt through VT-d.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VtdIoapic { Direct, Remapped { index: u16 }, Failed }
/// Result of allocating an x86 HPET FSB interrupt through VT-d.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VtdHpet { Direct, Remapped { address: u64, data: u32 }, Failed }

struct VtdBootUnit { unit: IommuUnit, regs: VtdRegisters, requesters: Vec<Bdf>, ioapic_source: Option<u16>, hpet_source: Option<u16>, tables: VtdTables, qi: Option<VtdQiQueue>, ir: Option<VtdIrTable> }
static MANAGER: Spinlock<Vec<VtdBootUnit>, Devices> = Spinlock::new(Vec::new());
/// Hardware/firmware admission for EIM.  This does not enable x2APIC: the
/// LAPIC owner must first put IOAPIC and HPET sources behind remapping too.
static EIM_CAPABLE: AtomicBool = AtomicBool::new(false);

/// Build, publish, and invalidate one VT-d identity domain per hardware unit.
///
/// # SAFETY
/// The caller must run before any requester can acquire PCI bus mastering.
/// # C: O(units + requesters + RAM leaves)
pub unsafe fn activate_vtd<R: ConfigSpaceReader>(reader: &R, requesters: &[Bdf], hhdm_offset: u64,
    regions: &[pmm::UsableRegion]) -> VtdActivation {
    EIM_CAPABLE.store(false, Ordering::Release);
    let units = published_vtd_units();
    if units.is_empty() { return VtdActivation::Bypass; }
    if units.iter().any(|unit| unit.kind != IommuKind::IntelVtd) { return VtdActivation::Failed; }

    let mut manager = Vec::new();
    for unit in units {
        let Some(regs) = (unsafe { VtdRegisters::map(unit.register_base, unit.register_pages) }) else { return VtdActivation::Failed; };
        let Some(mut tables) = VtdTables::new(hhdm_offset) else { return VtdActivation::Failed; };
        if !regs.cache_coherent() || !regs.supports_address_width(tables.address_width())
            || !tables.map_identity_regions(regions) { return VtdActivation::Failed; }
        let ir = if regs.supports_interrupt_remapping() && regs.supports_queued_invalidation() {
            let Some(table) = VtdIrTable::new(hhdm_offset, false) else { return activation_failed(&mut manager); };
            Some(table)
        } else { None };
        let qi = if regs.supports_queued_invalidation() {
            let Some(queue) = VtdQiQueue::new(hhdm_offset) else { return activation_failed(&mut manager); };
            if !regs.enable_queued_invalidation(&queue) {
                let _ = regs.disable_queued_invalidation();
                return activation_failed(&mut manager);
            }
            Some(queue)
        } else { None };
        manager.push(VtdBootUnit { unit, regs, requesters: Vec::new(), ioapic_source: None, hpet_source: None, tables, qi, ir });
    }
    for entry in manager.iter_mut() {
        for index in 0..intel_vtd_rmrr_count() {
            let Some(rmrr) = rmrr_for_unit(reader, requesters, index, entry.unit) else { continue; };
            let Some(len) = rmrr.end.checked_sub(rmrr.base).and_then(|bytes| bytes.checked_add(1)) else { return activation_failed(&mut manager); };
            if !entry.tables.map_identity_range(rmrr.base, len) { return activation_failed(&mut manager); }
        }
    }
    for bdf in requesters {
        let Some(unit) = intel_vtd_unit_for_bdf(reader, *bdf) else { continue; };
        let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return activation_failed(&mut manager); };
        if !entry.tables.attach(*bdf, INITIAL_DOMAIN_ID) { return activation_failed(&mut manager); }
        entry.requesters.push(*bdf);
    }
    if let Some(ioapic_id) = firmware::ioapic_id() {
        if let Some((unit, source_id)) = intel_vtd_ioapic_source(reader, ioapic_id) {
            let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return activation_failed(&mut manager); };
            entry.ioapic_source = Some(source_id);
        }
    }
    if let Some(hpet_id) = firmware::hpet_id() {
        if let Some((unit, source_id)) = intel_vtd_hpet_source(reader, hpet_id) {
            let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { return activation_failed(&mut manager); };
            entry.hpet_source = Some(source_id);
        }
    }
    for entry in manager.iter_mut() {
        if !entry.regs.set_root_table(entry.tables.root_pa()) || !invalidate(entry)
            || !entry.regs.enable_translation() { return activation_failed(&mut manager); }
        if let Some(ir) = entry.ir.as_ref() {
            if !entry.regs.set_interrupt_remap_table(ir.irta()) { return activation_failed(&mut manager); }
        }
    }
    let eim_capable = !firmware::acpi::dmar_x2apic_opt_out() && all_vtd_units_support_eim();
    *MANAGER.lock() = manager;
    EIM_CAPABLE.store(eim_capable, Ordering::Release);
    VtdActivation::Enabled
}

/// Undo every VT-d side effect created during an unsuccessful global
/// bootstrap. Linux's error paths disable translation before queued
/// invalidation (`disable_dmar_iommu()` and `dmar_disable_qi()`); preserving
/// that order keeps no hardware unit pointing at boot-owned tables after the
/// caller rejects PCI driver admission. # C: O(units * poll limit)
fn activation_failed(manager: &mut Vec<VtdBootUnit>) -> VtdActivation {
    for entry in manager.iter_mut() {
        let _ = entry.regs.disable_interrupt_remapping();
        let _ = entry.regs.disable_translation();
        let _ = entry.regs.disable_queued_invalidation();
    }
    manager.clear();
    EIM_CAPABLE.store(false, Ordering::Release);
    VtdActivation::Failed
}

/// Enable VT-d interrupt remapping only after the IRQ owner is ready to issue
/// remapped MSI/MSI-X messages. # C: O(units * poll limit)
pub fn enable_vtd_interrupt_remapping() -> bool {
    let mut manager = MANAGER.lock();
    for entry in manager.iter_mut() {
        if entry.ir.is_some() && !entry.regs.enable_interrupt_remapping() {
            rollback_interrupt_remapping(&mut manager);
            return false;
        }
    }
    true
}

/// Undo a partially completed all-unit IR transition.  VT-d has one remapping
/// enable per DRHD, so a later unit failing its status handshake must not
/// leave earlier units enabled while the caller declines to publish drivers.
/// Linux similarly invalidates the interrupt-entry cache before clearing IRE.
/// Best effort is deliberate here: this path is already handling a hardware
/// failure, but every reachable unit receives the architected teardown.
/// # C: O(units * poll limit)
fn rollback_interrupt_remapping(manager: &mut [VtdBootUnit]) {
    for entry in manager.iter_mut() {
        if entry.ir.is_none() { continue; }
        if let Some(queue) = entry.qi.as_mut() {
            let _ = entry.regs.invalidate_queued(queue);
        }
        let _ = entry.regs.disable_interrupt_remapping();
    }
}

/// Return whether firmware and every discovered VT-d unit admit EIM. Linux
/// uses the same all-IOMMU gate before selecting x2APIC interrupt remapping.
/// This result is deliberately separate from actually enabling x2APIC. # C: O(1)
pub fn vtd_eim_capable() -> bool { EIM_CAPABLE.load(Ordering::Acquire) }

/// Return whether this VT-d manager owns the exact PCI requester identity. # C: O(units * requesters)
pub fn owns(requester: Bdf) -> bool {
    MANAGER.lock().iter().any(|entry| entry.requesters.iter().any(|candidate| *candidate == requester))
}

/// Allocate one remapped x86 MSI for a requester owned by an IR-capable VT-d unit.
/// `None` means the unit is not using interrupt remapping, so the caller keeps
/// the ordinary APIC MSI encoding.
/// # C: O(units + IRTE scan + poll limit)
pub fn allocate_vtd_msi(requester: Bdf, vector: u8, destination_apic_id: u32) -> VtdMsi {
    let requester_id = (u16::from(requester.bus) << 8) | (u16::from(requester.device) << 3) | u16::from(requester.function);
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.requesters.iter().any(|candidate| *candidate == requester)) else { return VtdMsi::Direct; };
    let (Some(queue), Some(ir)) = (entry.qi.as_mut(), entry.ir.as_mut()) else { return VtdMsi::Direct; };
    let Some(index) = ir.allocate_msi(vector, destination_apic_id, requester_id) else { return VtdMsi::Failed; };
    if !entry.regs.invalidate_interrupt_entry(queue, index) { return VtdMsi::Failed; }
    let (address, data) = remapped_msi(index, 0);
    VtdMsi::Remapped { address, data }
}

/// Allocate one remapped IOAPIC route.  `Direct` leaves the caller on the
/// ordinary APIC route when firmware did not publish a trustworthy IOAPIC
/// scope or its owning VT-d unit lacks interrupt remapping. # C: O(units + IRTE scan + poll limit)
pub fn allocate_vtd_ioapic(vector: u8, destination_apic_id: u32) -> VtdIoapic {
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.ioapic_source.is_some()) else { return VtdIoapic::Direct; };
    let Some(source_id) = entry.ioapic_source else { return VtdIoapic::Direct; };
    let (Some(queue), Some(ir)) = (entry.qi.as_mut(), entry.ir.as_mut()) else { return VtdIoapic::Direct; };
    let Some(index) = ir.allocate_ioapic(vector, destination_apic_id, source_id) else { return VtdIoapic::Failed; };
    if !entry.regs.invalidate_interrupt_entry(queue, index) { return VtdIoapic::Failed; }
    VtdIoapic::Remapped { index }
}

/// Allocate one remapped HPET FSB message.  A published HPET block without a
/// trustworthy DMAR scope is refused, so no caller can silently program a
/// compatibility-format message after interrupt remapping is active.
/// # C: O(units + IRTE scan + poll limit)
pub fn allocate_vtd_hpet(vector: u8, destination_apic_id: u32) -> VtdHpet {
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.hpet_source.is_some()) else {
        return if firmware::hpet_pa() != 0 { VtdHpet::Failed } else { VtdHpet::Direct };
    };
    let Some(source_id) = entry.hpet_source else { return VtdHpet::Direct; };
    let (Some(queue), Some(ir)) = (entry.qi.as_mut(), entry.ir.as_mut()) else { return VtdHpet::Direct; };
    let Some(index) = ir.allocate_hpet(vector, destination_apic_id, source_id) else { return VtdHpet::Failed; };
    if !entry.regs.invalidate_interrupt_entry(queue, index) { return VtdHpet::Failed; }
    let (address, data) = remapped_msi(index, 0);
    VtdHpet::Remapped { address, data }
}

/// Install one live mapping constrained by the requester's inclusive DMA mask.
/// # C: O(pages * levels + poll limit)
pub fn map_dma_below(requester: Bdf, pa: u64, len: usize, mask: u64) -> Option<u64> {
    let (base, bytes, offset) = crate::dma_span::normalize_dma_span(pa, len)?;
    let mut manager = MANAGER.lock();
    let entry = manager.iter_mut().find(|entry| entry.requesters.iter().any(|candidate| *candidate == requester))?;
    let map = entry.tables.map_dma_below(base, bytes, pci::IOVA_PAGE_SIZE, mask)?;
    if !invalidate(entry) {
        if entry.tables.remove_for_invalidate(map) && invalidate(entry) {
            let _ = entry.tables.release_after_invalidate(map);
        }
        return None;
    }
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

fn published_vtd_units() -> Vec<IommuUnit> {
    let mut units = Vec::new();
    for index in 0..firmware::acpi::iommu_unit_count() {
        let Some(unit) = firmware::acpi::iommu_unit(index) else { continue; };
        append_unique_vtd(&mut units, unit);
    }
    units
}

fn append_unique_vtd(units: &mut Vec<IommuUnit>, unit: IommuUnit) {
    if unit.kind == IommuKind::IntelVtd && !units.iter().any(|current| *current == unit) { units.push(unit); }
}

/// Linux declines EIM if any DRHD lacks queued invalidation, interrupt
/// remapping, or EIM. Inspect the whole published topology, not just the
/// units that happened to receive a PCI requester in this boot scan. # C: O(units)
fn all_vtd_units_support_eim() -> bool {
    let count = firmware::acpi::iommu_unit_count();
    if count == 0 { return false; }
    for index in 0..count {
        let Some(unit) = firmware::acpi::iommu_unit(index) else { return false; };
        if unit.kind != IommuKind::IntelVtd { return false; }
        // SAFETY: firmware published the bounded register aperture for this DRHD.
        let Some(regs) = (unsafe { VtdRegisters::map(unit.register_base, unit.register_pages) }) else { return false; };
        if !eim_capability_set_admits(regs.supports_queued_invalidation(),
            regs.supports_interrupt_remapping(), regs.supports_extended_interrupt_mode()) { return false; }
    }
    true
}

const fn eim_capability_set_admits(queued_invalidation: bool, interrupt_remapping: bool,
    extended_interrupt_mode: bool) -> bool {
    queued_invalidation && interrupt_remapping && extended_interrupt_mode
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
        append_unique_vtd(&mut units, first);
        append_unique_vtd(&mut units, first);
        append_unique_vtd(&mut units, second);
        assert_eq!(units, alloc::vec![first, second]);
    }

    #[test] fn eim_requires_every_vtd_capability() {
        assert!(!eim_capability_set_admits(true, true, false));
        assert!(!eim_capability_set_admits(true, false, true));
        assert!(!eim_capability_set_admits(false, true, true));
        assert!(eim_capability_set_admits(true, true, true));
    }
}
