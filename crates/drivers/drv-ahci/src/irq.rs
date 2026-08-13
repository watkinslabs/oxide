//! AHCI completion endpoints backed by PCI-core-owned interrupt bindings.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use sched::live::wait_list::WaitList;

use crate::port::Ahci;
use crate::regs;

/// AHCI exposes at most 32 ports per host; every active port needs one
/// completion endpoint even though the PCI function has one shared vector.
const MAX_ENDPOINTS: usize = 32;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;

struct Endpoint {
    state: AtomicU8, abar_va: AtomicU64, port: AtomicU32, in_handler: AtomicU32,
    pis: AtomicU32, tfd: AtomicU32, complete: AtomicBool, wake: AtomicBool, waiters: WaitList,
    irq_count: AtomicU64,
}

impl Endpoint {
    const fn new() -> Self {
        Self { state: AtomicU8::new(ENDPOINT_FREE), abar_va: AtomicU64::new(0), port: AtomicU32::new(0),
            in_handler: AtomicU32::new(0), pis: AtomicU32::new(0), tfd: AtomicU32::new(0),
            complete: AtomicBool::new(false), wake: AtomicBool::new(false), waiters: WaitList::new(),
            irq_count: AtomicU64::new(0) }
    }
}

static ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [const { Endpoint::new() }; MAX_ENDPOINTS];

#[derive(Clone, Copy)]
pub(crate) struct IrqBinding { endpoint: usize, binding: Option<pci_irq::Binding> }

fn claim_endpoint(ctrl: &Ahci) -> Option<usize> {
    for (idx, endpoint) in ENDPOINTS.iter().enumerate() {
        if endpoint.state.compare_exchange(ENDPOINT_FREE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.abar_va.store(ctrl.abar_va(), Ordering::Release);
        endpoint.port.store(ctrl.port_index(), Ordering::Release);
        endpoint.in_handler.store(0, Ordering::Release);
        endpoint.pis.store(0, Ordering::Release);
        endpoint.tfd.store(0, Ordering::Release);
        endpoint.complete.store(false, Ordering::Release);
        endpoint.wake.store(false, Ordering::Release);
        endpoint.irq_count.store(0, Ordering::Release);
        return Some(idx);
    }
    None
}

fn release_endpoint(idx: usize) {
    let endpoint = &ENDPOINTS[idx];
    endpoint.abar_va.store(0, Ordering::Release);
    endpoint.port.store(0, Ordering::Release);
    endpoint.complete.store(false, Ordering::Release);
    endpoint.wake.store(false, Ordering::Release);
    endpoint.state.store(ENDPOINT_FREE, Ordering::Release);
}

fn hard_handler() {
    let mut raise = false;
    let mut hosts = [(0u64, 0u32); MAX_ENDPOINTS];
    let mut host_count = 0usize;
    for endpoint in &ENDPOINTS {
        if endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { continue; }
        endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
        let abar_va = endpoint.abar_va.load(Ordering::Acquire);
        let port = endpoint.port.load(Ordering::Acquire);
        let port_bit = 1u32 << port;
        // SAFETY: ACTIVE publishes the controller-owned ABAR mapping and teardown drains in_handler before unmapping it.
        let hba_is = unsafe { core::ptr::read_volatile((abar_va + regs::HBA_IS) as *const u32) };
        let mut known_host = false;
        for host in hosts.iter_mut().take(host_count) {
            if host.0 == abar_va { host.1 |= hba_is; known_host = true; break; }
        }
        if !known_host && host_count < hosts.len() {
            hosts[host_count] = (abar_va, hba_is);
            host_count += 1;
        }
        if hba_is & port_bit != 0 {
            let port_base = abar_va + regs::port_off(port);
            // SAFETY: ACTIVE publishes the selected port register block until synchronize_and_release completes.
            unsafe {
                let pis = core::ptr::read_volatile((port_base + regs::P_IS) as *const u32);
                let ci = core::ptr::read_volatile((port_base + regs::P_CI) as *const u32);
                let tfd = core::ptr::read_volatile((port_base + regs::P_TFD) as *const u32);
                core::ptr::write_volatile((port_base + regs::P_IS) as *mut u32, pis);
                endpoint.pis.fetch_or(pis, Ordering::AcqRel);
                endpoint.tfd.store(tfd, Ordering::Release);
                if regs::irq_finishes_slot(pis, ci, tfd) {
                    endpoint.complete.store(true, Ordering::Release);
                    endpoint.wake.store(true, Ordering::Release);
                    endpoint.irq_count.fetch_add(1, Ordering::Relaxed);
                    #[cfg(feature = "debug-boot")]
                    {
                        klog::write_raw(b"[INFO]  ahci: irq terminal port=");
                        klog::write_dec_u64(port as u64);
                        klog::write_raw(b"\n");
                    }
                    // Scheduler wake placement can take a remote runqueue
                    // path after SMP.  Publish only from hard-IRQ context;
                    // the registered BlockIo completion bottom half performs
                    // the task wake after this handler has released the HBA.
                    raise = true;
                }
            }
        }
        endpoint.in_handler.fetch_sub(1, Ordering::Release);
        endpoint.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    }
    for (abar_va, hba_is) in hosts.iter().take(host_count) {
        // SAFETY: every selected port cause was acknowledged above while its
        // endpoint retained the shared host mapping; acknowledge the HBA
        // level latch only after that complete host-wide pass.
        unsafe { core::ptr::write_volatile((*abar_va + regs::HBA_IS) as *mut u32, *hba_is); }
    }
    #[cfg(feature = "debug-boot")]
    if raise { klog::write_raw(b"[INFO]  ahci: irq host acked\n"); }
    // If the synchronous owner has not published a sleeping waiter, its
    // acquire-loaded completion bit is sufficient and there is no bottom-half
    // work to run from this IRQ tail.
    // Running BlockIo in that window re-enters scheduler-facing completion
    // machinery before the request owner has reached the wait protocol.
    let wake_waiter = raise && ENDPOINTS.iter().any(|endpoint|
        endpoint.waiters.has_waiters());
    #[cfg(feature = "debug-boot")]
    if raise && !wake_waiter { klog::write_raw(b"[INFO]  ahci: irq no waiter\n"); }
    if wake_waiter {
        block::completion::raise();
        #[cfg(feature = "debug-boot")]
        klog::write_raw(b"[INFO]  ahci: irq softirq raised\n");
    }
}

/// Bind one AHCI controller through the PCI IRQ owner. # C: O(N_caps)
pub(crate) fn bind(bdf: pci::Bdf, ctrl: &Ahci) -> Option<IrqBinding> {
    let shared = ENDPOINTS.iter().any(|endpoint|
        endpoint.state.load(Ordering::Acquire) != ENDPOINT_FREE
            && endpoint.abar_va.load(Ordering::Acquire) == ctrl.abar_va());
    let endpoint = claim_endpoint(ctrl)?;
    if shared {
        ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
        ctrl.enable_interrupts();
        return Some(IrqBinding { endpoint, binding: None });
    }
    let table = pci_irq::BarMapping { bar: 5, base_va: ctrl.abar_va(), bytes: ctrl.abar_map_bytes(), offset: ctrl.abar_offset() };
    let Some(binding) = pci_irq::request(bdf, table, arch_irq::DeviceAction::Ahci, hard_handler) else {
        release_endpoint(endpoint);
        return None;
    };
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
    ctrl.enable_interrupts();
    Some(IrqBinding { endpoint, binding: Some(binding) })
}

impl IrqBinding {
    /// Whether this endpoint owns the function-level PCI interrupt binding. # C: O(1)
    pub(crate) const fn owns_host_irq(self) -> bool { self.binding.is_some() }
    /// Reset software completion state before a new doorbell. # C: O(1)
    pub(crate) fn prepare_command(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        endpoint.pis.store(0, Ordering::Release);
        endpoint.tfd.store(0, Ordering::Release);
        endpoint.wake.store(false, Ordering::Release);
        endpoint.complete.store(false, Ordering::Release);
    }

    /// Observe terminal IRQ state for the current command. # C: O(1)
    pub(crate) fn completed(self) -> bool { ENDPOINTS[self.endpoint].complete.load(Ordering::Acquire) }

    /// Classify the current terminal IRQ state. # C: O(1)
    pub(crate) fn failed(self) -> bool {
        let endpoint = &ENDPOINTS[self.endpoint];
        regs::irq_status_failed(endpoint.pis.load(Ordering::Acquire), endpoint.tfd.load(Ordering::Acquire))
    }

    /// Consume one hard-handler bottom-half wake request. # C: O(1)
    pub(crate) fn take_wake(self) -> bool { ENDPOINTS[self.endpoint].wake.swap(false, Ordering::AcqRel) }

    /// Command-completion wait queue owned by this IRQ endpoint. # C: O(1)
    pub(crate) fn waiters(self) -> &'static WaitList { &ENDPOINTS[self.endpoint].waiters }

    #[cfg(feature = "debug-boot")]
    /// Count terminal IRQ observations. # C: O(1)
    pub(crate) fn completion_count(self) -> u64 { ENDPOINTS[self.endpoint].irq_count.load(Ordering::Acquire) }

    /// Mask AHCI sources and prevent a new hard-handler acquisition. # C: O(N_slots)
    pub(crate) fn begin_release(self, ctrl: &Ahci) {
        if self.owns_host_irq() { ctrl.disable_interrupts(); }
        let endpoint = &ENDPOINTS[self.endpoint];
        loop {
            match endpoint.state.compare_exchange(ENDPOINT_ACTIVE, ENDPOINT_SETUP, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) | Err(ENDPOINT_SETUP) => break,
                Err(ENDPOINT_HANDLING) => core::hint::spin_loop(),
                Err(_) => break,
            }
        }
    }

    /// Drain the hard handler, release the PCI-owned vector, then free the endpoint. # C: O(handler)
    pub(crate) fn synchronize_and_release(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        while endpoint.in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
        if let Some(binding) = self.binding { binding.release(); }
        release_endpoint(self.endpoint);
    }
}
