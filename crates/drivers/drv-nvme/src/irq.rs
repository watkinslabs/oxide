//! NVMe single-vector MSI-X/MSI binding and allocation-free hard completion endpoints.

#![cfg(any(target_os = "oxide-kernel", test))]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

const MAX_ENDPOINTS: usize = 8;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;
const PCI_RID_BUS_SHIFT: u32 = 8;
const PCI_RID_DEVICE_SHIFT: u32 = 3;

struct Endpoint {
    state: AtomicU8,
    in_handler: AtomicU32,
    complete: AtomicBool,
    wake: AtomicBool,
    irq_count: AtomicU64,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(ENDPOINT_FREE),
            in_handler: AtomicU32::new(0),
            complete: AtomicBool::new(false),
            wake: AtomicBool::new(false),
            irq_count: AtomicU64::new(0),
        }
    }
}

static ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [const { Endpoint::new() }; MAX_ENDPOINTS];

#[derive(Clone, Copy)]
enum Interrupt { Msi { cap_off: u8 }, Msix { cap_off: u8, entry_va: u64 } }
#[derive(Clone, Copy)]
pub(crate) struct IrqBinding {
    endpoint: usize,
    irq: u32,
    bdf: pci::Bdf,
    interrupt: Interrupt,
    intx_previous: u16,
}

fn requester_id(bdf: pci::Bdf) -> u32 {
    ((bdf.bus as u32) << PCI_RID_BUS_SHIFT)
        | ((bdf.device as u32) << PCI_RID_DEVICE_SHIFT)
        | bdf.function as u32
}

fn claim_endpoint() -> Option<usize> {
    for (idx, endpoint) in ENDPOINTS.iter().enumerate() {
        if endpoint.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.in_handler.store(0, Ordering::Release);
        endpoint.complete.store(false, Ordering::Release);
        endpoint.wake.store(false, Ordering::Release);
        endpoint.irq_count.store(0, Ordering::Release);
        return Some(idx);
    }
    None
}

fn release_endpoint(idx: usize) {
    let endpoint = &ENDPOINTS[idx];
    endpoint.complete.store(false, Ordering::Release);
    endpoint.wake.store(false, Ordering::Release);
    endpoint.state.store(ENDPOINT_FREE, Ordering::Release);
}

fn hard_handler_for(idx: usize) {
    let endpoint = &ENDPOINTS[idx];
    if endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
    endpoint.complete.store(true, Ordering::Release);
    endpoint.wake.store(true, Ordering::Release);
    endpoint.irq_count.fetch_add(1, Ordering::Relaxed);
    endpoint.in_handler.fetch_sub(1, Ordering::Release);
    endpoint.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    block::completion::raise();
}

fn handler_0() { hard_handler_for(0); }
fn handler_1() { hard_handler_for(1); }
fn handler_2() { hard_handler_for(2); }
fn handler_3() { hard_handler_for(3); }
fn handler_4() { hard_handler_for(4); }
fn handler_5() { hard_handler_for(5); }
fn handler_6() { hard_handler_for(6); }
fn handler_7() { hard_handler_for(7); }
const HANDLERS: [fn(); MAX_ENDPOINTS] = [handler_0, handler_1, handler_2, handler_3, handler_4, handler_5, handler_6, handler_7];

fn msix_entry_offset(cap: pci::MsixCap, map_bytes: u64, bar0_off: u64) -> Option<u64> {
    if cap.table_bir != 0 { return None; }
    let entry = pci::msix_table_entry_offset(cap, 0)?;
    bar0_off.checked_add(entry)?.checked_add(pci::MSIX_TABLE_ENTRY_BYTES).filter(|end| *end <= map_bytes).map(|_| entry)
}

fn bind_msix<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, mmio: &mmio_map::Mapping, bar0_off: u64) -> Option<IrqBinding> {
    let caps = pci::capabilities(r, bdf);
    let cap_off = caps.find(pci::CAP_ID_MSIX)?.cfg_off;
    let entry_off = msix_entry_offset(pci::decode_msix_cap(r, bdf, cap_off)?, mmio.bytes(), bar0_off)?;
    let entry_va = mmio.base_va().checked_add(bar0_off)?.checked_add(entry_off)?;
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    let Some(endpoint) = claim_endpoint() else { arch_irq::free_pci_msi(message.irq); return None; };
    if !arch_irq::register_pci_msi_handler(message.irq, arch_irq::DeviceAction::Nvme, HANDLERS[endpoint]) {
        release_endpoint(endpoint); arch_irq::free_pci_msi(message.irq); return None;
    }
    let intx_previous = pci::set_intx_disabled(r, bdf, true);
    if let Some(msi) = caps.find(pci::CAP_ID_MSI) { let _ = pci::disable_msi(r, bdf, msi.cfg_off); }
    let cfg = cap_off & 0xfc;
    r.write32(bdf, cfg, pci::msix_control_enable_masked(r.read32(bdf, cfg)));
    let _ = r.read32(bdf, cfg);
    // SAFETY: `entry_va` is a checked, aligned MSI-X entry inside the caller-owned BAR0 mapping.
    unsafe {
        write_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32, pci::MSIX_VECTOR_CONTROL_MASKED);
        let _ = read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
        write_volatile((entry_va + pci::MSIX_MESSAGE_ADDR_LOW_OFF) as *mut u32, message.address as u32);
        write_volatile((entry_va + pci::MSIX_MESSAGE_ADDR_HIGH_OFF) as *mut u32, (message.address >> 32) as u32);
        write_volatile((entry_va + pci::MSIX_MESSAGE_DATA_OFF) as *mut u32, message.data);
        let _ = read_volatile((entry_va + pci::MSIX_MESSAGE_DATA_OFF) as *const u32);
        write_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32, 0);
        let _ = read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
    }
    r.write32(bdf, cfg, pci::msix_control_value(r.read32(bdf, cfg), true));
    let _ = r.read32(bdf, cfg);
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
    Some(IrqBinding { endpoint, irq: message.irq, bdf, interrupt: Interrupt::Msix { cap_off, entry_va }, intx_previous })
}

fn bind_msi<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) -> Option<IrqBinding> {
    let cap_off = pci::capabilities(r, bdf).find(pci::CAP_ID_MSI)?.cfg_off;
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    let Some(endpoint) = claim_endpoint() else {
        arch_irq::free_pci_msi(message.irq);
        return None;
    };
    if !arch_irq::register_pci_msi_handler(message.irq, arch_irq::DeviceAction::Nvme, HANDLERS[endpoint]) {
        release_endpoint(endpoint);
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    let intx_previous = pci::set_intx_disabled(r, bdf, true);
    if !pci::program_msi_single(r, bdf, cap_off, message.address, message.data) {
        let _ = pci::restore_intx_disabled(r, bdf, intx_previous);
        arch_irq::free_pci_msi(message.irq);
        release_endpoint(endpoint);
        return None;
    }
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
    Some(IrqBinding { endpoint, irq: message.irq, bdf, interrupt: Interrupt::Msi { cap_off }, intx_previous })
}

fn bind_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, mmio: &mmio_map::Mapping, bar0_off: u64) -> Option<IrqBinding> {
    bind_msix(r, bdf, mmio, bar0_off).or_else(|| bind_msi(r, bdf))
}

/// Bind a non-polled NVMe completion queue to one PCI MSI-X or MSI vector. # C: O(N_caps)
pub(crate) fn bind(bdf: pci::Bdf, mmio: &mmio_map::Mapping, bar0_off: u64) -> Option<IrqBinding> {
    #[cfg(target_arch = "x86_64")]
    { bind_with(&hal_x86_64::pci::EcamPci::from_published()?, bdf, mmio, bar0_off) }
    #[cfg(target_arch = "aarch64")]
    { bind_with(&hal_aarch64::pci::EcamPci::from_published()?, bdf, mmio, bar0_off) }
}

fn disable_config_with<R: pci::ConfigSpaceReader>(r: &R, binding: IrqBinding) {
    match binding.interrupt {
        Interrupt::Msi { cap_off } => { let _ = pci::disable_msi(r, binding.bdf, cap_off); }
        Interrupt::Msix { cap_off, entry_va } => {
            // SAFETY: entry VA remains in the controller-owned BAR mapping until NVMe teardown finishes.
            unsafe { write_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32, pci::MSIX_VECTOR_CONTROL_MASKED); let _ = read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32); }
            let cfg = cap_off & 0xfc;
            r.write32(binding.bdf, cfg, pci::msix_control_value(r.read32(binding.bdf, cfg), false));
            let _ = r.read32(binding.bdf, cfg);
        }
    }
    let _ = pci::restore_intx_disabled(r, binding.bdf, binding.intx_previous);
}

fn disable_config(binding: IrqBinding) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { disable_config_with(&r, binding); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { disable_config_with(&r, binding); }
}

#[cfg(test)] mod tests {
    use super::*;
    fn cap(bir: u8, offset: u32) -> pci::MsixCap { pci::MsixCap { enabled: false, function_mask: false, table_size: 1, table_bir: bir, table_offset: offset, pba_bir: 0, pba_offset: 0 } }
    #[test] fn msix_entry_must_lie_inside_the_full_bar_mapping() {
        assert_eq!(msix_entry_offset(cap(0, 0x2000), 0x3010, 0x1000), Some(0x2000));
        assert_eq!(msix_entry_offset(cap(0, 0x2000), 0x300f, 0x1000), None);
        assert_eq!(msix_entry_offset(cap(1, 0x2000), 0x4000, 0), None);
    }
}

impl IrqBinding {
    /// Controller-local NVMe vector number for CREATE I/O CQ. # C: O(1)
    pub(crate) fn vector(self) -> u16 { 0 }

    /// Reset software completion state before ringing the I/O SQ doorbell. # C: O(1)
    pub(crate) fn prepare_command(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        endpoint.wake.store(false, Ordering::Release);
        endpoint.complete.store(false, Ordering::Release);
    }

    /// Observe the current command's interrupt completion. # C: O(1)
    pub(crate) fn completed(self) -> bool { ENDPOINTS[self.endpoint].complete.load(Ordering::Acquire) }

    /// Consume the hard-handler request for a process-safe wake. # C: O(1)
    pub(crate) fn take_wake(self) -> bool { ENDPOINTS[self.endpoint].wake.swap(false, Ordering::AcqRel) }

    /// Mask this PCI message and prevent future hard-handler acquisition. # C: O(N_slots)
    pub(crate) fn mask_and_free(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        loop {
            match endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) | Err(ENDPOINT_SETUP) => break,
                Err(ENDPOINT_HANDLING) => core::hint::spin_loop(),
                Err(_) => break,
            }
        }
        disable_config(self);
        arch_irq::free_pci_msi(self.irq);
    }

    /// Drain a claimed hard handler before releasing the endpoint. # C: O(handler)
    pub(crate) fn synchronize_and_release(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        while endpoint.in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
        release_endpoint(self.endpoint);
    }
}
