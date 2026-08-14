//! PCI-core ownership of MSI and MSI-X vector allocation, programming, and teardown.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicPtr, Ordering};

mod multi_msi;

/// One BAR mapping that contains an MSI-X table. Drivers retain ownership of
/// the mapping until [`Binding::release`] returns. # C: O(1)
#[derive(Clone, Copy)]
pub struct BarMapping { pub bar: u8, pub base_va: u64, pub bytes: u64, pub offset: u64 }

#[derive(Clone, Copy)]
enum Mode {
    Msi { cap_off: u8 },
    Msix { cap_off: u8, entry_va: u64 },
    #[cfg(target_arch = "x86_64")]
    Intx,
}

/// PCI interrupt delivery mechanism selected for a binding. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery { Msi, Msix, Intx }

/// A firmware-resolved PCI INTx route. `gsi` is an interrupt-controller
/// input, not the legacy PCI interrupt-line register. PCI routes are level
/// triggered and active-low unless firmware explicitly says otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntxRoute { pub gsi: u32, pub level: bool, pub active_low: bool }

/// Firmware route lookup installed by the PCI root-complex owner. It mirrors
/// the PCI core's separation between ACPI `_PRT` resolution and driver IRQ
/// allocation.
pub type IntxResolver = fn(pci::Bdf, u8) -> Option<IntxRoute>;

#[cfg(target_arch = "x86_64")]
static INTX_RESOLVER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Publish the ACPI-backed INTx resolver before PCI drivers probe. # C: O(1)
pub fn set_intx_resolver(resolver: IntxResolver) {
    #[cfg(target_arch = "x86_64")]
    INTX_RESOLVER.store(resolver as *mut (), Ordering::Release);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = resolver;
}

/// One PCI-core-owned interrupt message. A driver only owns its handler and
/// synchronizes it before releasing this binding. # C: O(1)
#[derive(Clone, Copy)]
pub struct Binding {
    bdf: pci::Bdf,
    irq: u32,
    prior_command: u16,
    mode: Mode,
    irqs: [u32; MSI_MAX_MESSAGES],
    irq_count: u8,
}

const MSI_MAX_MESSAGES: usize = 32;

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

/// Request one MSI vector without an INTx fallback. Platform-owned functions
/// that report through a message-signaled event register must not depend on a
/// firmware PCI routing entry. # C: O(capabilities)
pub fn request_msi_only(bdf: pci::Bdf, action: arch_irq::DeviceAction, handler: fn()) -> Option<Binding> {
    #[cfg(target_arch = "x86_64")]
    {
        let reader = hal_x86_64::pci::EcamPci::from_published()?;
        let cap = pci::capabilities(&reader, bdf).find(pci::CAP_ID_MSI)?;
        request_msi(&reader, bdf, cap.cfg_off, action, handler)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let reader = hal_aarch64::pci::EcamPci::from_published()?;
        let cap = pci::capabilities(&reader, bdf).find(pci::CAP_ID_MSI)?;
        request_msi(&reader, bdf, cap.cfg_off, action, handler)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = (bdf, action, handler); None }
}

/// Request one MSI vector whose hard handler receives the binding-owned
/// context argument. # C: O(capabilities)
pub fn request_msi_only_context(bdf: pci::Bdf, action: arch_irq::DeviceAction,
    handler: fn(usize), arg: usize) -> Option<Binding> {
    #[cfg(target_arch = "x86_64")]
    {
        let reader = hal_x86_64::pci::EcamPci::from_published()?;
        let cap = pci::capabilities(&reader, bdf).find(pci::CAP_ID_MSI)?;
        request_msi_context(&reader, bdf, cap.cfg_off, action, handler, arg)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let reader = hal_aarch64::pci::EcamPci::from_published()?;
        let cap = pci::capabilities(&reader, bdf).find(pci::CAP_ID_MSI)?;
        request_msi_context(&reader, bdf, cap.cfg_off, action, handler, arg)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = (bdf, action, handler, arg); None }
}

/// Request the exact device-relative MSI message selected by a PCIe port
/// capability. The binding owns every lower message in its MSI block and
/// dispatches only `message_number`. # C: O(messages * irq_slots)
pub fn request_msi_only_context_message(bdf: pci::Bdf, message_number: u8,
    action: arch_irq::DeviceAction, handler: fn(usize), arg: usize) -> Option<Binding> {
    #[cfg(target_arch = "x86_64")]
    {
        let reader = hal_x86_64::pci::EcamPci::from_published()?;
        let cap = pci::capabilities(&reader, bdf).find(pci::CAP_ID_MSI)?;
        request_msi_context_message(&reader, bdf, cap.cfg_off, message_number, action, handler, arg)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let reader = hal_aarch64::pci::EcamPci::from_published()?;
        let cap = pci::capabilities(&reader, bdf).find(pci::CAP_ID_MSI)?;
        request_msi_context_message(&reader, bdf, cap.cfg_off, message_number, action, handler, arg)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = (bdf, message_number, action, handler, arg); None }
}

/// Request a legacy INTx vector from a route already resolved by the PCI
/// root-complex owner. This is intentionally separate from the PCI
/// interrupt-line byte, which is not a routable interrupt-controller input.
/// # C: O(N_vectors + IRTE scan)
pub fn request_intx(bdf: pci::Bdf, route: IntxRoute, action: arch_irq::DeviceAction,
    handler: fn()) -> Option<Binding> {
    #[cfg(target_arch = "x86_64")]
    { request_intx_x86(bdf, route, action, handler) }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (bdf, route, action, handler); None }
}

/// Linux `pci_irq_vector(dev, 0)` equivalent for this single-vector owner.
/// # C: O(1)
pub const fn irq(binding: Binding) -> u32 { binding.irq }
/// Returns the transport selected by the PCI IRQ owner.
/// # C: O(1)
pub const fn delivery(binding: Binding) -> Delivery { match binding.mode { Mode::Msi { .. } => Delivery::Msi, Mode::Msix { .. } => Delivery::Msix, #[cfg(target_arch = "x86_64")] Mode::Intx => Delivery::Intx } }

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
        if matches!(self.mode, Mode::Intx) {
            free_binding_irqs(&self);
            return;
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { release_with(&r, self); }
        #[cfg(target_arch = "aarch64")]
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { release_with(&r, self); }
        free_binding_irqs(&self);
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
    let message = arch_irq::alloc_pci_msi(group.bdf, entry.vector as u32)?;
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
    if let Some(cap) = caps.find(pci::CAP_ID_MSI) {
        if let Some(binding) = request_msi(r, bdf, cap.cfg_off, action, handler) { return Some(binding); }
    }
    let pin = pci::read8(r, bdf, pci::uapi::INTERRUPT_PIN_OFF);
    let (route_bdf, route_pin) = pci::swizzle_intx_to_root(r, bdf, pin)?;
    resolved_intx(route_bdf, route_pin).and_then(|route| request_intx(bdf, route, action, handler))
}

fn resolved_intx(bdf: pci::Bdf, pin: u8) -> Option<IntxRoute> {
    #[cfg(target_arch = "x86_64")]
    {
        let raw = INTX_RESOLVER.load(Ordering::Acquire);
        if raw.is_null() { return None; }
        // SAFETY: set_intx_resolver accepts only an ABI-compatible Rust fn and
        // never clears it while PCI probing may use the callback.
        let resolve: IntxResolver = unsafe { core::mem::transmute(raw) };
        return resolve(bdf, pin);
    }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (bdf, pin); None }
}

#[cfg(target_arch = "x86_64")]
fn request_intx_x86(bdf: pci::Bdf, route: IntxRoute, action: arch_irq::DeviceAction,
    handler: fn()) -> Option<Binding> {
    let vector = arch_irq::alloc_x86_vector()?;
    if !arch_irq::register_pci_msi_handler(u32::from(vector), action, handler) {
        let _ = arch_irq::free_x86_vector(vector);
        return None;
    }
    // SAFETY: the handler is installed before the source is unmasked; PCI
    // root-complex serialization is still held during early driver probe.
    let routed = unsafe { arch_irq::program_x86_intx_gsi(route.gsi, vector, 0, route.level, route.active_low) };
    if !routed {
        arch_irq::free_pci_msi(u32::from(vector));
        return None;
    }
    Some(single_binding(bdf, u32::from(vector), 0, Mode::Intx))
}

fn request_msi<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, cap_off: u8,
    action: arch_irq::DeviceAction, handler: fn()) -> Option<Binding> {
    let message = arch_irq::alloc_pci_msi(bdf, 0)?;
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
    Some(single_binding(bdf, message.irq, prior_command, Mode::Msi { cap_off }))
}

fn request_msi_context<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, cap_off: u8,
    action: arch_irq::DeviceAction, handler: fn(usize), arg: usize) -> Option<Binding> {
    let message = arch_irq::alloc_pci_msi(bdf, 0)?;
    if !arch_irq::register_pci_msi_context_handler(message.irq, action, handler, arg) {
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    let prior_command = pci::set_intx_disabled(r, bdf, true);
    if !pci::program_msi_single(r, bdf, cap_off, message.address, message.data) {
        let _ = pci::restore_intx_disabled(r, bdf, prior_command);
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    Some(single_binding(bdf, message.irq, prior_command, Mode::Msi { cap_off }))
}

fn request_msi_context_message<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, cap_off: u8,
    message_number: u8, action: arch_irq::DeviceAction, handler: fn(usize), arg: usize) -> Option<Binding> {
    let cap = pci::decode_msi_cap(r, bdf, cap_off)?;
    let block = multi_msi::allocate(bdf, message_number, cap.multiple_message_capable)?;
    let target = block.message(message_number as usize)?;
    if !arch_irq::register_pci_msi_context_handler(target.irq, action, handler, arg) {
        block.release();
        return None;
    }
    let prior_command = pci::set_intx_disabled(r, bdf, true);
    if !block.program(r, bdf, cap_off, cap, message_number as usize) {
        let _ = pci::restore_intx_disabled(r, bdf, prior_command);
        block.release();
        return None;
    }
    let mut irqs = [0; MSI_MAX_MESSAGES];
    for index in 0..block.count() { irqs[index] = block.message(index)?.irq; }
    Some(Binding { bdf, irq: target.irq, prior_command, mode: Mode::Msi { cap_off }, irqs, irq_count: block.count() as u8 })
}

fn single_binding(bdf: pci::Bdf, irq: u32, prior_command: u16, mode: Mode) -> Binding {
    let mut irqs = [0; MSI_MAX_MESSAGES];
    irqs[0] = irq;
    Binding { bdf, irq, prior_command, mode, irqs, irq_count: 1 }
}

fn free_binding_irqs(binding: &Binding) {
    for irq in &binding.irqs[..binding.irq_count as usize] { arch_irq::free_pci_msi(*irq); }
}

fn request_msix<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, msi_cap: Option<u8>,
    cap_off: u8, entry_va: u64, action: arch_irq::DeviceAction, handler: fn()) -> Option<Binding> {
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  pci-irq: msix bdf=");
        klog::write_dec_u64(bdf.bus as u64); klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64); klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64); klog::write_raw(b" entry=");
        klog::write_hex_u64(entry_va); klog::write_raw(b"\n");
    }
    let message = arch_irq::alloc_pci_msi(bdf, 0)?;
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
    Some(single_binding(bdf, message.irq, prior_command, Mode::Msix { cap_off, entry_va }))
}

fn release_with<R: pci::ConfigSpaceReader>(r: &R, binding: Binding) {
    match binding.mode {
        Mode::Msi { cap_off } => { let _ = pci::disable_msi(r, binding.bdf, cap_off); }
        Mode::Msix { cap_off, entry_va } => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[INFO]  pci-irq: msix release entry="); klog::write_hex_u64(entry_va);
                #[cfg(target_arch = "x86_64")]
                { use hal::{MmuOps, Va}; let mapped = <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(entry_va)).is_some(); klog::write_raw(if mapped { b" mapped\n" } else { b" absent\n" }); }
                #[cfg(target_arch = "aarch64")]
                { use hal::{MmuOps, Va}; let mapped = <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::translate(Va(entry_va)).is_some(); klog::write_raw(if mapped { b" mapped\n" } else { b" absent\n" }); }
            }
            write_msix_mask(entry_va);
            let cfg = cap_off & 0xfc;
            r.write32(binding.bdf, cfg, pci::msix_control_value(r.read32(binding.bdf, cfg), false));
            let _ = r.read32(binding.bdf, cfg);
        }
        #[cfg(target_arch = "x86_64")]
        Mode::Intx => {}
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

    fn test_route(bdf: pci::Bdf, _: u8) -> Option<IntxRoute> {
        (bdf.device == 2).then_some(IntxRoute { gsi: 19, level: true, active_low: true })
    }

    #[test]
    fn resolver_returns_only_firmware_owned_routes() {
        set_intx_resolver(test_route);
        let hit = pci::Bdf { segment: 0, bus: 0, device: 2, function: 0 };
        let miss = pci::Bdf { device: 3, ..hit };
        assert_eq!(resolved_intx(hit, 1), Some(IntxRoute { gsi: 19, level: true, active_low: true }));
        assert_eq!(resolved_intx(miss, 1), None);
    }
}
