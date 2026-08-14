use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{VtdIrTable, VtdQiQueue, VtdRegisters, VtdTables, intel_vtd_hpet_source, intel_vtd_ioapic_source, intel_vtd_rmrr_count, intel_vtd_rmrr_for_bdf, intel_vtd_unit_for_bdf, remapped_msi, vtd_dma_groups};
use crate::vtd_cache::maintenance_available;
use firmware::acpi::{IommuKind, IommuUnit};
use pci::{Bdf, ConfigSpaceReader};
use sync::{Devices, Spinlock};

const FIRST_DOMAIN_ID: u16 = 1;

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

struct VtdBootUnit { unit: IommuUnit, regs: VtdRegisters, requesters: Vec<Bdf>, ioapic_sources: Vec<(u8, u16)>, hpet_source: Option<u16>, tables: VtdTables, qi: Option<VtdQiQueue>, ir: Option<Box<VtdIrTable>> }
static MANAGER: Spinlock<Vec<VtdBootUnit>, Devices> = Spinlock::new(Vec::new());
/// Hardware/firmware admission for EIM.  This does not enable x2APIC: the
/// LAPIC owner must first put IOAPIC and HPET sources behind remapping too.
static EIM_CAPABLE: AtomicBool = AtomicBool::new(false);
/// Hardware interrupt remapping is enabled only after every firmware I/O APIC
/// has a source scope in an IR-capable unit.
static INTERRUPT_REMAP_ENABLED: AtomicBool = AtomicBool::new(false);
static FAULT_RECORDS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "debug-boot")]
fn trace_failure(stage: &'static [u8]) {
    klog::write_raw(b"[WARN] vtd: "); klog::write_raw(stage); klog::write_raw(b"\n");
}
#[cfg(not(feature = "debug-boot"))]
fn trace_failure(_: &'static [u8]) {}
#[cfg(feature = "debug-boot")]
fn trace_stage(stage: &'static [u8]) {
    klog::write_raw(b"[INFO]  vtd: "); klog::write_raw(stage); klog::write_raw(b"\n");
}
#[cfg(not(feature = "debug-boot"))]
fn trace_stage(_: &'static [u8]) {}
#[cfg(feature = "debug-boot")]
fn trace_dma_map(requester: Bdf, pa: u64, iova: u64) {
    klog::write_raw(b"[INFO]  vtd: dma bdf=");
    klog::write_dec_u64(u64::from(requester.bus)); klog::write_raw(b":");
    klog::write_dec_u64(u64::from(requester.device)); klog::write_raw(b".");
    klog::write_dec_u64(u64::from(requester.function)); klog::write_raw(b" pa=");
    klog::write_hex_u64(pa); klog::write_raw(b" iova="); klog::write_hex_u64(iova); klog::write_raw(b"\n");
}
#[cfg(not(feature = "debug-boot"))]
fn trace_dma_map(_: Bdf, _: u64, _: u64) {}

/// Build, publish, and invalidate one VT-d identity domain per hardware unit.
///
/// # SAFETY
/// The caller must run before any requester can acquire PCI bus mastering.
/// # C: O(units + requesters + RAM leaves)
#[inline(never)]
pub unsafe fn activate_vtd<R: ConfigSpaceReader>(reader: &R, requesters: &[Bdf], aliases: &pci::DmaAliases, hhdm_offset: u64,
    regions: &[pmm::UsableRegion]) -> VtdActivation {
    EIM_CAPABLE.store(false, Ordering::Release);
    INTERRUPT_REMAP_ENABLED.store(false, Ordering::Release);
    let units = published_vtd_units();
    if units.is_empty() { return VtdActivation::Bypass; }
    if units.iter().any(|unit| unit.kind != IommuKind::IntelVtd) { trace_failure(b"mixed unit"); return VtdActivation::Failed; }

    let mut manager = Vec::new();
    for unit in units {
        trace_stage(b"unit setup");
        let Some(regs) = (unsafe { VtdRegisters::map(unit.register_base, unit.register_pages) }) else { trace_failure(b"register map"); return VtdActivation::Failed; };
        let coherent = regs.cache_coherent();
        if !maintenance_available(coherent) { trace_failure(b"cache maintenance"); return VtdActivation::Failed; }
        let Some(address_width) = regs.select_address_width(VtdTables::maximum_address_width()) else { trace_failure(b"address width"); return VtdActivation::Failed; };
        let Some(tables) = VtdTables::new(hhdm_offset, coherent, address_width, regs.page_sizes()) else { trace_failure(b"table allocation"); return VtdActivation::Failed; };
        // Linux disables firmware-pre-enabled IR/translation/QI state before
        // it replaces their table bases.  Do this only after replacement
        // allocations and mappings succeeded, so an allocation failure leaves
        // the firmware configuration intact.
        if !regs.quiesce_firmware_state() { trace_failure(b"firmware quiesce"); return activation_failed(&mut manager); }
        let ir = if regs.supports_interrupt_remapping() && regs.supports_queued_invalidation() {
            let Some(table) = VtdIrTable::new(hhdm_offset, coherent, false) else { trace_failure(b"interrupt table"); return activation_failed(&mut manager); };
            Some(Box::new(table))
        } else { None };
        let qi = if regs.supports_queued_invalidation() {
            let Some(queue) = VtdQiQueue::new(hhdm_offset, coherent) else { trace_failure(b"queued invalidation allocation"); return activation_failed(&mut manager); };
            if !regs.enable_queued_invalidation(&queue) {
                let _ = regs.disable_queued_invalidation();
                trace_failure(b"queued invalidation enable"); return activation_failed(&mut manager);
            }
            Some(queue)
        } else { None };
        manager.push(VtdBootUnit { unit, regs, requesters: Vec::new(), ioapic_sources: Vec::new(), hpet_source: None, tables, qi, ir });
    }
    trace_stage(b"domain setup");
    for entry in manager.iter_mut() {
        let unit_requesters: Vec<Bdf> = requesters.iter().copied().filter(|bdf|
            intel_vtd_unit_for_bdf(reader, *bdf) == Some(entry.unit)).collect();
        for (index, group) in vtd_dma_groups(reader, &unit_requesters, aliases).iter().enumerate() {
            let Some(domain_id) = u16::try_from(index).ok().and_then(|id| FIRST_DOMAIN_ID.checked_add(id)) else { trace_failure(b"domain identifier"); return activation_failed(&mut manager); };
            if !entry.tables.install_group(domain_id, group, regions) { trace_failure(b"domain install"); return activation_failed(&mut manager); }
            entry.requesters.extend_from_slice(group);
        }
        for requester in &unit_requesters {
            for index in 0..intel_vtd_rmrr_count() {
                let Some(rmrr) = intel_vtd_rmrr_for_bdf(reader, *requester, index) else { continue; };
                let Some(len) = rmrr.end.checked_sub(rmrr.base).and_then(|bytes| bytes.checked_add(1)) else { trace_failure(b"reserved range length"); return activation_failed(&mut manager); };
                if !entry.tables.map_identity_range(*requester, rmrr.base, len) { trace_failure(b"reserved range map"); return activation_failed(&mut manager); }
            }
        }
        for requester in &unit_requesters {
            if !entry.tables.attach_requester(*requester) { trace_failure(b"requester attach"); return activation_failed(&mut manager); }
            for alias in aliases.for_requester(*requester) {
                if !entry.tables.attach_alias(*requester, alias) { trace_failure(b"alias attach"); return activation_failed(&mut manager); }
            }
        }
    }
    trace_stage(b"platform scopes");
    for index in 0..firmware::ioapic_count() {
        let Some(ioapic_id) = firmware::ioapic(index).map(|ioapic| ioapic.id) else { continue; };
        if let Some((unit, source_id)) = intel_vtd_ioapic_source(reader, ioapic_id) {
            let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { trace_failure(b"ioapic unit"); return activation_failed(&mut manager); };
            entry.ioapic_sources.push((ioapic_id, source_id));
        }
    }
    if let Some(hpet_id) = firmware::hpet_id() {
        if let Some((unit, source_id)) = intel_vtd_hpet_source(reader, hpet_id) {
            let Some(entry) = manager.iter_mut().find(|entry| entry.unit == unit) else { trace_failure(b"hpet unit"); return activation_failed(&mut manager); };
            entry.hpet_source = Some(source_id);
        }
    }
    trace_stage(b"hardware enable");
    for entry in manager.iter_mut() {
        if !entry.regs.set_root_table(entry.tables.root_pa()) { trace_failure(b"root table"); return activation_failed(&mut manager); }
        if !invalidate(entry) { trace_failure(b"translation invalidate"); return activation_failed(&mut manager); }
        if !entry.regs.enable_translation() { trace_failure(b"translation enable"); return activation_failed(&mut manager); }
        if let Some(ir) = entry.ir.as_ref() {
            if !entry.regs.set_interrupt_remap_table(ir.irta()) { trace_failure(b"interrupt table install"); return activation_failed(&mut manager); }
        }
    }
    trace_stage(b"ready");
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
        let _ = entry.regs.disable_fault_interrupts();
        let _ = entry.regs.disable_interrupt_remapping();
        let _ = entry.regs.disable_translation();
        let _ = entry.regs.disable_queued_invalidation();
    }
    manager.clear();
    EIM_CAPABLE.store(false, Ordering::Release);
    VtdActivation::Failed
}

/// Program every live DRHD with one architecture-owned primary-fault MSI. # C: O(units)
pub fn enable_vtd_fault_interrupts(address: u64, data: u32) -> bool {
    let manager = MANAGER.lock();
    for entry in manager.iter() {
        if !entry.regs.enable_fault_interrupts(address, data) {
            for entry in manager.iter() { let _ = entry.regs.disable_fault_interrupts(); }
            return false;
        }
    }
    true
}

/// Drain each active unit's VT-d primary fault records. # C: O(units + fault records)
pub fn poll_vtd_faults(visitor: &mut impl FnMut(crate::VtdFault)) -> bool {
    let manager = MANAGER.lock(); let mut complete = true;
    for entry in manager.iter() { complete &= entry.regs.drain_primary_faults(visitor); }
    complete
}

/// Drain VT-d primary faults from the architecture MSI handler. # C: O(units + fault records)
pub fn handle_vtd_fault_interrupt() {
    let mut count = |_| { FAULT_RECORDS.fetch_add(1, Ordering::Relaxed); };
    let _ = poll_vtd_faults(&mut count);
}

/// Return the number of primary fault records consumed from live VT-d units. # C: O(1)
pub fn vtd_fault_records() -> u64 { FAULT_RECORDS.load(Ordering::Acquire) }

/// Enable VT-d interrupt remapping only after the IRQ owner is ready to issue
/// remapped MSI/MSI-X messages. # C: O(units * poll limit)
pub fn enable_vtd_interrupt_remapping() -> bool {
    let mut manager = MANAGER.lock();
    if !all_ioapics_remappable(&manager) { return true; }
    for entry in manager.iter_mut() {
        if entry.ir.is_some() && !entry.regs.enable_interrupt_remapping() {
            rollback_interrupt_remapping(&mut manager);
            return false;
        }
    }
    INTERRUPT_REMAP_ENABLED.store(true, Ordering::Release);
    true
}

/// Require the complete firmware I/O-APIC inventory before turning on a
/// unit's global interrupt-remapping enable bit. # C: O(units * IOAPICs)
fn all_ioapics_remappable(manager: &[VtdBootUnit]) -> bool {
    let count = firmware::ioapic_count();
    if count == 0 { return manager.iter().all(|entry| entry.ir.is_some()); }
    manager.iter().all(|entry| entry.ir.is_some()) && (0..count).all(|index| {
        firmware::ioapic(index).is_some_and(|ioapic|
            manager.iter().any(|entry| entry.ioapic_sources.iter().any(|(id, _)| *id == ioapic.id)))
    })
}

/// Undo a partially completed all-unit IR transition.  VT-d has one remapping
/// enable per DRHD, so a later unit failing its status handshake must not
/// leave earlier units enabled while the caller declines to publish drivers.
/// Linux similarly invalidates the interrupt-entry cache before clearing IRE.
/// Best effort is deliberate here: this path is already handling a hardware
/// failure, but every reachable unit receives the architected teardown.
/// # C: O(units * poll limit)
fn rollback_interrupt_remapping(manager: &mut [VtdBootUnit]) {
    INTERRUPT_REMAP_ENABLED.store(false, Ordering::Release);
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

pub(crate) fn active() -> bool { !MANAGER.lock().is_empty() }

/// Allocate one remapped x86 MSI for a requester owned by an IR-capable VT-d unit.
/// `None` means the unit is not using interrupt remapping, so the caller keeps
/// the ordinary APIC MSI encoding.
/// # C: O(units + IRTE scan + poll limit)
pub fn allocate_vtd_msi(requester: Bdf, vector: u8, destination_apic_id: u32) -> VtdMsi {
    if !INTERRUPT_REMAP_ENABLED.load(Ordering::Acquire) { return VtdMsi::Direct; }
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
pub fn allocate_vtd_ioapic(ioapic_id: u8, vector: u8, destination_apic_id: u32) -> VtdIoapic {
    if !INTERRUPT_REMAP_ENABLED.load(Ordering::Acquire) { return VtdIoapic::Direct; }
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.ioapic_sources.iter().any(|(id, _)| *id == ioapic_id)) else { return VtdIoapic::Direct; };
    let Some((_, source_id)) = entry.ioapic_sources.iter().find(|(id, _)| *id == ioapic_id).copied() else { return VtdIoapic::Direct; };
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
    if !INTERRUPT_REMAP_ENABLED.load(Ordering::Acquire) { return VtdHpet::Direct; }
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
    let map = entry.tables.map_dma_below(requester, base, bytes, pci::IOVA_PAGE_SIZE, mask)?;
    if !invalidate(entry) {
        if entry.tables.remove_for_invalidate(requester, map) && invalidate(entry) {
            let _ = entry.tables.release_after_invalidate(requester, map);
        }
        return None;
    }
    let iova = map.iova.start.checked_add(offset)?;
    trace_dma_map(requester, pa, iova);
    Some(iova)
}

/// Remove one exact VT-d mapping only after the IOTLB has consumed its removal. # C: O(pages * levels + poll limit)
pub fn unmap_dma(requester: Bdf, iova: u64, len: usize) -> bool {
    let page = pci::IOVA_PAGE_SIZE;
    let base = iova & !(page - 1);
    let offset = iova - base;
    let Some(bytes) = offset.checked_add(len as u64).and_then(|n| n.checked_add(page - 1)).map(|n| n & !(page - 1)) else { return false; };
    let mut manager = MANAGER.lock();
    let Some(entry) = manager.iter_mut().find(|entry| entry.requesters.iter().any(|candidate| *candidate == requester)) else { return false; };
    let Some(map) = entry.tables.mapping(requester, base) else { return false; };
    if map.iova.len != bytes || !entry.tables.remove_for_invalidate(requester, map) { return false; }
    invalidate(entry) && entry.tables.release_after_invalidate(requester, map)
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

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn deduplicates_vtd_units_without_merging_segments() {
        let first = IommuUnit { kind: IommuKind::IntelVtd, segment: 1, source_id: 0, event_msi: 0, register_base: 0xfed9_0000, register_pages: 1, include_all: false };
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
