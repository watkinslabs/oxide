//! NVMe completion endpoints backed by PCI-core-owned interrupt bindings.

#![cfg(any(target_os = "oxide-kernel", test))]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

const MAX_ENDPOINTS: usize = 8;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;

struct Endpoint {
    state: AtomicU8,
    in_handler: AtomicU32,
    wake: AtomicBool,
    irq_count: AtomicU64,
    cq_pa: AtomicU64, cq_head: AtomicU32, cq_phase: AtomicBool,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(ENDPOINT_FREE),
            in_handler: AtomicU32::new(0),
            wake: AtomicBool::new(false),
            irq_count: AtomicU64::new(0),
            cq_pa: AtomicU64::new(0), cq_head: AtomicU32::new(0), cq_phase: AtomicBool::new(true),
        }
    }
}

static ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [const { Endpoint::new() }; MAX_ENDPOINTS];

#[derive(Clone, Copy)]
pub(crate) struct IrqBinding { endpoint: usize, binding: pci_irq::Binding }

fn claim_endpoint() -> Option<usize> {
    for (idx, endpoint) in ENDPOINTS.iter().enumerate() {
        if endpoint.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.in_handler.store(0, Ordering::Release);
        endpoint.wake.store(false, Ordering::Release);
    endpoint.irq_count.store(0, Ordering::Release);
        endpoint.cq_pa.store(0, Ordering::Release);
        return Some(idx);
    }
    None
}

fn release_endpoint(idx: usize) {
    let endpoint = &ENDPOINTS[idx];
    endpoint.wake.store(false, Ordering::Release);
    endpoint.state.store(ENDPOINT_FREE, Ordering::Release);
}

fn hard_handler_for(idx: usize) {
    let endpoint = &ENDPOINTS[idx];
    if endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
    #[cfg(target_os = "oxide-kernel")]
    {
        let pa = endpoint.cq_pa.load(Ordering::Acquire);
        let head = endpoint.cq_head.load(Ordering::Acquire);
        let phase = endpoint.cq_phase.load(Ordering::Acquire);
        if pa != 0 {
            let h = crate::platform::hhdm();
            if h != 0 {
            pmm::dma::invalidate_from_device(h + pa + u64::from(head) * 16, 16);
            // SAFETY: the configured cursor is a live controller-owned CQE;
            // the completion phase is read before any process-context reap.
            let status = unsafe { core::ptr::read_volatile((h + pa + u64::from(head) * 16 + 12) as *const u32) };
            if crate::regs::cqe_pending(status, phase) {
                endpoint.wake.store(true, Ordering::Release);
                endpoint.irq_count.fetch_add(1, Ordering::Relaxed);
            }
            }
        }
    }
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

/// Bind one NVMe completion queue through the PCI IRQ owner. # C: O(N_caps)
pub(crate) fn bind(bdf: pci::Bdf, mmio: &mmio_map::Mapping, bar0_off: u64) -> Option<IrqBinding> {
    let endpoint = claim_endpoint()?;
    let table = pci_irq::BarMapping { bar: 0, base_va: mmio.base_va(), bytes: mmio.bytes(), offset: bar0_off };
    let Some(binding) = pci_irq::request(bdf, table, arch_irq::DeviceAction::Nvme, HANDLERS[endpoint]) else {
        release_endpoint(endpoint);
        return None;
    };
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
    Some(IrqBinding { endpoint, binding })
}

impl IrqBinding {
    /// Controller-local NVMe vector number for CREATE I/O CQ. # C: O(1)
    pub(crate) fn vector(&self) -> u16 { 0 }
    pub(crate) fn configure_cq(&self, pa: u64, head: u32, phase: bool) { let e = &ENDPOINTS[self.endpoint]; e.cq_pa.store(pa, Ordering::Release); e.cq_head.store(head, Ordering::Release); e.cq_phase.store(phase, Ordering::Release); }

    /// Consume the hard-handler request for a process-safe wake. # C: O(1)
    pub(crate) fn take_wake(&self) -> bool { ENDPOINTS[self.endpoint].wake.swap(false, Ordering::AcqRel) }

    /// Prevent a new hard-handler acquisition before releasing the PCI vector. # C: O(N_slots)
    pub(crate) fn begin_release(&self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        loop {
            match endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) | Err(ENDPOINT_SETUP) => break,
                Err(ENDPOINT_HANDLING) => core::hint::spin_loop(),
                Err(_) => break,
            }
        }
    }

    /// Stop completion handling and drain a handler that was already running.
    /// The PCI vector remains allocated for a live controller reset. # C: O(handler)
    pub(crate) fn suspend(&self) {
        self.begin_release();
        let endpoint = &ENDPOINTS[self.endpoint];
        while endpoint.in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
        endpoint.wake.store(false, Ordering::Release);
        endpoint.cq_pa.store(0, Ordering::Release);
    }

    /// Resume completion handling after the rebuilt queue cursor is installed.
    /// # C: O(1)
    pub(crate) fn resume(&self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        let _ = endpoint.state.compare_exchange(ENDPOINT_SETUP, ENDPOINT_ACTIVE, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Drain the hard handler, release the PCI-owned vector, then free the endpoint. # C: O(handler)
    pub(crate) fn synchronize_and_release(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        while endpoint.in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
        self.binding.release();
        release_endpoint(self.endpoint);
    }
}
