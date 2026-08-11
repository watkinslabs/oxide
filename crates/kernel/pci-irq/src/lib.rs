//! PCI-core ownership of MSI and MSI-X vector allocation, programming, and teardown.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

/// One BAR mapping that contains an MSI-X table. Drivers retain ownership of
/// the mapping until [`Binding::release`] returns. # C: O(1)
#[derive(Clone, Copy)]
pub struct BarMapping { pub bar: u8, pub base_va: u64, pub bytes: u64, pub offset: u64 }

#[derive(Clone, Copy)]
enum Mode { Msi { cap_off: u8 }, Msix { cap_off: u8, entry_va: u64 } }

/// One PCI-core-owned interrupt message. A driver only owns its handler and
/// synchronizes it before releasing this binding. # C: O(1)
#[derive(Clone, Copy)]
pub struct Binding { bdf: pci::Bdf, irq: u32, prior_command: u16, mode: Mode }

/// Caller-retained mapping of one MSI-X table entry. The PCI IRQ owner
/// validates the table BAR and vector index before programming this address.
/// # C: O(1)
#[derive(Clone, Copy)]
pub struct MsixEntry { pub bar: u8, pub vector: u16, pub entry_va: u64 }

#[derive(Clone, Copy)]
struct MsixVector { irq: u32, entry_va: u64 }

/// PCI-owned MSI-X allocation group. It mirrors one device-level vector
/// allocation: entries are added by device-relative vector number, unmasked
/// after the device is ready, and released together. # C: O(N_vectors)
pub struct MsixGroup {
    bdf: pci::Bdf,
    cap_off: u8,
    table_bar: u8,
    table_offset: u32,
    table_size: u16,
    prior_command: u16,
    vectors: Vec<MsixVector>,
}

/// Request one vector using MSI-X first, MSI second. The caller supplies a
/// table BAR when MSI-X may be present; a missing or incompatible table falls
/// back to MSI. # C: O(capabilities)
pub fn request(bdf: pci::Bdf, table: BarMapping, action: arch_irq::DeviceAction,
    handler: fn()) -> Option<Binding> {
    #[cfg(target_arch = "x86_64")]
    { request_with(&hal_x86_64::pci::EcamPci::from_published()?, bdf, table, action, handler) }
    #[cfg(target_arch = "aarch64")]
    { request_with(&hal_aarch64::pci::EcamPci::from_published()?, bdf, table, action, handler) }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = (bdf, table, action, handler); None }
}

/// Linux `pci_irq_vector(dev, 0)` equivalent for this single-vector owner.
/// # C: O(1)
pub const fn irq(binding: Binding) -> u32 { binding.irq }

/// Start one MSI-X allocation group for a PCI function. The caller adds each
/// requested device-relative vector with [`MsixGroup::bind`]. # C: O(capabilities)
pub fn begin_msix(bdf: pci::Bdf) -> Option<MsixGroup> {
    #[cfg(target_arch = "x86_64")]
    { begin_msix_with(&hal_x86_64::pci::EcamPci::from_published()?, bdf) }
    #[cfg(target_arch = "aarch64")]
    { begin_msix_with(&hal_aarch64::pci::EcamPci::from_published()?, bdf) }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = bdf; None }
}

impl Binding {
    /// Mask and disable the PCI message, restore INTx state, then free its
    /// architecture vector. The driver must quiesce its handler first. # C: O(1)
    pub fn release(self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { release_with(&r, self); }
        #[cfg(target_arch = "aarch64")]
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { release_with(&r, self); }
        arch_irq::free_pci_msi(self.irq);
    }
}

impl MsixGroup {
    /// Return the table BAR and byte offset for one device-relative vector. # C: O(1)
    pub fn entry_offset(&self, vector: u16) -> Option<(u8, u64)> {
        if vector >= self.table_size { return None; }
        let bytes = (vector as u64).checked_mul(pci::MSIX_TABLE_ENTRY_BYTES)?;
        (self.table_offset as u64).checked_add(bytes).map(|offset| (self.table_bar, offset))
    }

    /// Allocate and program one device-relative MSI-X vector. # C: O(N_vectors)
    pub fn bind(&mut self, entry: MsixEntry, action: arch_irq::DeviceAction,
        handler: fn()) -> Option<u32> {
        if entry.bar != self.table_bar || entry.vector >= self.table_size
            || self.vectors.iter().any(|vector| vector.entry_va == entry.entry_va) { return None; }
        #[cfg(target_arch = "x86_64")]
        { bind_msix_with(&hal_x86_64::pci::EcamPci::from_published()?, self, entry, action, handler) }
        #[cfg(target_arch = "aarch64")]
        { bind_msix_with(&hal_aarch64::pci::EcamPci::from_published()?, self, entry, action, handler) }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = (entry, action, handler); None }
    }

    /// Allow the device to deliver all vectors programmed in this group. # C: O(1)
    pub fn unmask(&self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { unmask_msix_with(&r, self); }
        #[cfg(target_arch = "aarch64")]
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { unmask_msix_with(&r, self); }
    }

    /// Mask entries, disable MSI-X, restore INTx state, then free every
    /// architecture vector. Call after all handlers are quiesced. # C: O(N_vectors)
    pub fn release(self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { release_msix_group_with(&r, &self); }
        #[cfg(target_arch = "aarch64")]
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { release_msix_group_with(&r, &self); }
        for vector in self.vectors { arch_irq::free_pci_msi(vector.irq); }
    }
}

fn requester_id(bdf: pci::Bdf) -> u32 {
    ((bdf.bus as u32) << 8) | ((bdf.device as u32) << 3) | bdf.function as u32
}

fn begin_msix_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) -> Option<MsixGroup> {
    let caps = pci::capabilities(r, bdf);
    let cap_off = caps.find(pci::CAP_ID_MSIX)?.cfg_off;
    let cap = pci::decode_msix_cap(r, bdf, cap_off)?;
    let prior_command = pci::set_intx_disabled(r, bdf, true);
    if let Some(msi_cap) = caps.find(pci::CAP_ID_MSI) { let _ = pci::disable_msi(r, bdf, msi_cap.cfg_off); }
    let cfg = cap_off & 0xfc;
    r.write32(bdf, cfg, pci::msix_control_enable_masked(r.read32(bdf, cfg)));
    let _ = r.read32(bdf, cfg);
    Some(MsixGroup { bdf, cap_off, table_bar: cap.table_bir, table_offset: cap.table_offset, table_size: cap.table_size,
        prior_command, vectors: Vec::new() })
}

fn bind_msix_with<R: pci::ConfigSpaceReader>(_: &R, group: &mut MsixGroup,
    entry: MsixEntry, action: arch_irq::DeviceAction, handler: fn()) -> Option<u32> {
    let message = arch_irq::alloc_pci_msi(requester_id(group.bdf), entry.vector as u32)?;
    if !arch_irq::register_pci_msi_handler(message.irq, action, handler) {
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    write_msix_entry(entry.entry_va, message.address, message.data);
    group.vectors.push(MsixVector { irq: message.irq, entry_va: entry.entry_va });
    Some(message.irq)
}

fn unmask_msix_with<R: pci::ConfigSpaceReader>(r: &R, group: &MsixGroup) {
    let cfg = group.cap_off & 0xfc;
    r.write32(group.bdf, cfg, pci::msix_control_value(r.read32(group.bdf, cfg), true));
    let _ = r.read32(group.bdf, cfg);
}

fn release_msix_group_with<R: pci::ConfigSpaceReader>(r: &R, group: &MsixGroup) {
    for vector in &group.vectors { write_msix_mask(vector.entry_va); }
    let cfg = group.cap_off & 0xfc;
    r.write32(group.bdf, cfg, pci::msix_control_value(r.read32(group.bdf, cfg), false));
    let _ = r.read32(group.bdf, cfg);
    let _ = pci::restore_intx_disabled(r, group.bdf, group.prior_command);
}

fn request_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, table: BarMapping,
    action: arch_irq::DeviceAction, handler: fn()) -> Option<Binding> {
    let caps = pci::capabilities(r, bdf);
    if let Some(cap) = caps.find(pci::CAP_ID_MSIX).and_then(|c| pci::decode_msix_cap(r, bdf, c.cfg_off).map(|m| (c.cfg_off, m))) {
        if let Some(entry_va) = msix_entry_va(cap.1, table) {
            if let Some(binding) = request_msix(r, bdf, caps.find(pci::CAP_ID_MSI).map(|c| c.cfg_off),
                cap.0, entry_va, action, handler) { return Some(binding); }
        }
    }
    request_msi(r, bdf, caps.find(pci::CAP_ID_MSI)?.cfg_off, action, handler)
}

fn request_msi<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, cap_off: u8,
    action: arch_irq::DeviceAction, handler: fn()) -> Option<Binding> {
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    if !arch_irq::register_pci_msi_handler(message.irq, action, handler) {
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    let prior_command = pci::set_intx_disabled(r, bdf, true);
    if !pci::program_msi_single(r, bdf, cap_off, message.address, message.data) {
        let _ = pci::restore_intx_disabled(r, bdf, prior_command);
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    Some(Binding { bdf, irq: message.irq, prior_command, mode: Mode::Msi { cap_off } })
}

fn request_msix<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, msi_cap: Option<u8>,
    cap_off: u8, entry_va: u64, action: arch_irq::DeviceAction, handler: fn()) -> Option<Binding> {
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    if !arch_irq::register_pci_msi_handler(message.irq, action, handler) {
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    let prior_command = pci::set_intx_disabled(r, bdf, true);
    if let Some(msi_cap) = msi_cap { let _ = pci::disable_msi(r, bdf, msi_cap); }
    let cfg = cap_off & 0xfc;
    r.write32(bdf, cfg, pci::msix_control_enable_masked(r.read32(bdf, cfg)));
    let _ = r.read32(bdf, cfg);
    write_msix_entry(entry_va, message.address, message.data);
    r.write32(bdf, cfg, pci::msix_control_value(r.read32(bdf, cfg), true));
    let _ = r.read32(bdf, cfg);
    Some(Binding { bdf, irq: message.irq, prior_command, mode: Mode::Msix { cap_off, entry_va } })
}

fn release_with<R: pci::ConfigSpaceReader>(r: &R, binding: Binding) {
    match binding.mode {
        Mode::Msi { cap_off } => { let _ = pci::disable_msi(r, binding.bdf, cap_off); }
        Mode::Msix { cap_off, entry_va } => {
            write_msix_mask(entry_va);
            let cfg = cap_off & 0xfc;
            r.write32(binding.bdf, cfg, pci::msix_control_value(r.read32(binding.bdf, cfg), false));
            let _ = r.read32(binding.bdf, cfg);
        }
    }
    let _ = pci::restore_intx_disabled(r, binding.bdf, binding.prior_command);
}

fn msix_entry_va(cap: pci::MsixCap, table: BarMapping) -> Option<u64> {
    if cap.table_bir != table.bar { return None; }
    let entry = pci::msix_table_entry_offset(cap, 0)?;
    let off = table.offset.checked_add(entry)?;
    off.checked_add(pci::MSIX_TABLE_ENTRY_BYTES).filter(|end| *end <= table.bytes)?;
    table.base_va.checked_add(off)
}

fn write_msix_entry(entry_va: u64, address: u64, data: u32) {
    // SAFETY: PCI core validated the MSI-X entry lies entirely inside the driver-retained BAR mapping.
    unsafe {
        write_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32, pci::MSIX_VECTOR_CONTROL_MASKED);
        let _ = read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
        write_volatile((entry_va + pci::MSIX_MESSAGE_ADDR_LOW_OFF) as *mut u32, address as u32);
        write_volatile((entry_va + pci::MSIX_MESSAGE_ADDR_HIGH_OFF) as *mut u32, (address >> 32) as u32);
        write_volatile((entry_va + pci::MSIX_MESSAGE_DATA_OFF) as *mut u32, data);
        let _ = read_volatile((entry_va + pci::MSIX_MESSAGE_DATA_OFF) as *const u32);
        write_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32, 0);
        let _ = read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
    }
}

fn write_msix_mask(entry_va: u64) {
    // SAFETY: this binding retains the validated MSI-X table entry until PCI teardown completes.
    unsafe {
        write_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32, pci::MSIX_VECTOR_CONTROL_MASKED);
        let _ = read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cap(bar: u8, off: u32) -> pci::MsixCap { pci::MsixCap { enabled: false, function_mask: false, table_size: 1, table_bir: bar, table_offset: off, pba_bir: 0, pba_offset: 0 } }
    #[test]
    fn table_entry_must_be_inside_the_declared_bar() {
        let table = BarMapping { bar: 0, base_va: 0x1000, bytes: 0x3000, offset: 0x1000 };
        assert_eq!(msix_entry_va(cap(0, 0x1000), table), Some(0x3000));
        assert_eq!(msix_entry_va(cap(1, 0), table), None);
    }

    #[test]
    fn group_reports_only_declared_device_relative_vectors() {
        let group = MsixGroup { bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 }, cap_off: 0,
            table_bar: 2, table_offset: 0x2000, table_size: 2, prior_command: 0,
            vectors: Vec::new() };
        assert_eq!(group.entry_offset(0), Some((2, 0x2000)));
        assert_eq!(group.entry_offset(1), Some((2, 0x2010)));
        assert_eq!(group.entry_offset(2), None);
    }
}
