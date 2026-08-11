//! NVMe single-MSI binding and allocation-free hard completion endpoints.

#![cfg(target_os = "oxide-kernel")]

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
pub(crate) struct IrqBinding {
    endpoint: usize,
    irq: u32,
    bdf: pci::Bdf,
    cap_off: u8,
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

fn bind_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) -> Option<IrqBinding> {
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
    Some(IrqBinding { endpoint, irq: message.irq, bdf, cap_off, intx_previous })
}

/// Bind a non-polled NVMe I/O completion queue to one PCI MSI vector. # C: O(N_caps)
pub(crate) fn bind(bdf: pci::Bdf) -> Option<IrqBinding> {
    #[cfg(target_arch = "x86_64")]
    { bind_with(&hal_x86_64::pci::EcamPci::from_published()?, bdf) }
    #[cfg(target_arch = "aarch64")]
    { bind_with(&hal_aarch64::pci::EcamPci::from_published()?, bdf) }
}

fn disable_config(binding: IrqBinding) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
        let _ = pci::disable_msi(&r, binding.bdf, binding.cap_off);
        let _ = pci::restore_intx_disabled(&r, binding.bdf, binding.intx_previous);
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
        let _ = pci::disable_msi(&r, binding.bdf, binding.cap_off);
        let _ = pci::restore_intx_disabled(&r, binding.bdf, binding.intx_previous);
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
