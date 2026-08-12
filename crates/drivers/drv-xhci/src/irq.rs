//! One-vector MSI-X/MSI ownership for a halted xHCI controller.
//!
//! The vector is installed before the controller is allowed to execute.  Event
//! consumption and the Run transition are deliberately a later atomic slice:
//! an enabled controller may not outlive this binding or its DMA pages.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::controller::{ERDP, ERDP_EHB, STS_EINT, USBSTS};
use crate::platform::{DmaPage, Mmio};
use crate::regs::interrupter_offset;
use crate::ring::{TRB_BYTES, TRB_CYCLE, TRBS_PER_SEGMENT};

const MAX_ENDPOINTS: usize = 8;
const FREE: u8 = 0;
const SETUP: u8 = 1;
const ACTIVE: u8 = 2;
const HANDLING: u8 = 3;

struct Endpoint {
    state: AtomicU8,
    in_handler: AtomicU32,
    mmio_va: AtomicU64,
    status_offset: AtomicU64,
    erdp_offset: AtomicU64,
    event_va: AtomicU64,
    event_pa: AtomicU64,
    bar_bytes: AtomicU64,
    max_ports: AtomicU8,
    port_changes: AtomicU64,
    command_completion_pa: AtomicU64,
    command_completion_status: AtomicU32,
    transfer_completion_pa: AtomicU64,
    transfer_completion_meta: AtomicU64,
    dequeue: AtomicU32,
    cycle: AtomicBool,
}
impl Endpoint {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE), in_handler: AtomicU32::new(0),
            mmio_va: AtomicU64::new(0), status_offset: AtomicU64::new(0), erdp_offset: AtomicU64::new(0),
            event_va: AtomicU64::new(0), event_pa: AtomicU64::new(0), bar_bytes: AtomicU64::new(0), max_ports: AtomicU8::new(0), port_changes: AtomicU64::new(0), command_completion_pa: AtomicU64::new(0), command_completion_status: AtomicU32::new(0), transfer_completion_pa: AtomicU64::new(0), transfer_completion_meta: AtomicU64::new(0), dequeue: AtomicU32::new(0), cycle: AtomicBool::new(true),
        }
    }
}
static ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [const { Endpoint::new() }; MAX_ENDPOINTS];

#[derive(Clone, Copy)]
pub(crate) struct Binding { endpoint: usize, binding: pci_irq::Binding }

fn hard_handler_for(index: usize) {
    let endpoint = &ENDPOINTS[index];
    if endpoint.state.compare_exchange(ACTIVE, HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    let mut transfer_event = false;
    endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
    let base = endpoint.mmio_va.load(Ordering::Acquire);
    let event_va = endpoint.event_va.load(Ordering::Acquire);
    let event_pa = endpoint.event_pa.load(Ordering::Acquire);
    if base != 0 && event_va != 0 && event_pa != 0 {
        let status_offset = endpoint.status_offset.load(Ordering::Acquire);
        // SAFETY: binding arms only validated offsets in the owned BAR mapping.
        let status = unsafe { read_volatile((base + status_offset) as *const u32) };
        if status != u32::MAX && status & STS_EINT != 0 {
            // SAFETY: USBSTS event is write-one-to-clear and this offset was validated above.
            unsafe { write_volatile((base + status_offset) as *mut u32, STS_EINT); }
            // SAFETY: event_va is a retained DmaPage direct-map address.  DMA
            // coherency must precede every observation of controller-owned TRBs.
            pmm::dma::invalidate_from_device(event_va, TRBS_PER_SEGMENT * TRB_BYTES);
            let mut dequeue = endpoint.dequeue.load(Ordering::Relaxed) as usize;
            let mut cycle = endpoint.cycle.load(Ordering::Relaxed);
            let mut consumed = 0;
            while consumed < TRBS_PER_SEGMENT {
                // SAFETY: each control dword is in the retained 4KiB event page.
                let control = unsafe { read_volatile((event_va + (dequeue * TRB_BYTES + 12) as u64) as *const u32) };
                if (control & TRB_CYCLE != 0) != cycle { break; }
                // SAFETY: the parameter dword is in the same validated event TRB.
                let parameter = unsafe { read_volatile((event_va + (dequeue * TRB_BYTES) as u64) as *const u32) };
                let kind = (control >> crate::ring::TRB_TYPE_SHIFT) & 0x3f;
                if kind == crate::ring::TRB_TYPE_COMMAND_COMPLETION {
                    // SAFETY: both dwords belong to the same controller-owned event TRB.
                    let parameter_hi = unsafe { read_volatile((event_va + (dequeue * TRB_BYTES + 4) as u64) as *const u32) };
                    let status = unsafe { read_volatile((event_va + (dequeue * TRB_BYTES + 8) as u64) as *const u32) };
                    let completion = status >> 24;
                    let slot = control >> 24;
                    endpoint.command_completion_status.store(completion | (slot << 8), Ordering::Relaxed);
                    endpoint.command_completion_pa.store(parameter as u64 | ((parameter_hi as u64) << 32), Ordering::Release);
                }
                if kind == crate::ring::TRB_TYPE_TRANSFER_EVENT {
                    let parameter_hi = unsafe { read_volatile((event_va + (dequeue * TRB_BYTES + 4) as u64) as *const u32) };
                    let status = unsafe { read_volatile((event_va + (dequeue * TRB_BYTES + 8) as u64) as *const u32) };
                    let meta = (status & 0x00ff_ffff) as u64 | (((status >> 24) as u64) << 24)
                        | ((((control >> 16) & 0x1f) as u64) << 32) | (((control >> 24) as u64) << 40);
                    endpoint.transfer_completion_meta.store(meta, Ordering::Relaxed);
                    endpoint.transfer_completion_pa.store(parameter as u64 | ((parameter_hi as u64) << 32), Ordering::Release);
                    transfer_event = true;
                }
                if let Some(port) = crate::ports::event_port_id(parameter, control, endpoint.max_ports.load(Ordering::Acquire)) {
                    let operational = status_offset - USBSTS;
                    if let Some(portsc_offset) = crate::ports::portsc_offset(operational, port, endpoint.max_ports.load(Ordering::Acquire))
                        .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= endpoint.bar_bytes.load(Ordering::Acquire)))
                    {
                        // SAFETY: `portsc_offset` is a checked PORTSC dword in the owned BAR.
                        let portsc = unsafe { read_volatile((base + portsc_offset) as *const u32) };
                        let acknowledge = crate::ports::acknowledge_changes(portsc);
                        if acknowledge != 0 {
                            // SAFETY: PORTSC change bits are explicitly write-one-to-clear.
                            unsafe { write_volatile((base + portsc_offset) as *mut u32, acknowledge); }
                        }
                        endpoint.port_changes.fetch_or(1u64 << (port - 1), Ordering::Release);
                    }
                }
                dequeue += 1;
                consumed += 1;
                if dequeue == TRBS_PER_SEGMENT { dequeue = 0; cycle = !cycle; }
            }
            endpoint.dequeue.store(dequeue as u32, Ordering::Release);
            endpoint.cycle.store(cycle, Ordering::Release);
            let erdp = event_pa + (dequeue * TRB_BYTES) as u64 | ERDP_EHB;
            let erdp_offset = endpoint.erdp_offset.load(Ordering::Acquire);
            // SAFETY: ERDP is an aligned, validated runtime interrupter register.
            unsafe {
                write_volatile((base + erdp_offset) as *mut u32, erdp as u32);
                write_volatile((base + erdp_offset + 4) as *mut u32, (erdp >> 32) as u32);
            }
        }
    }
    endpoint.in_handler.fetch_sub(1, Ordering::Release);
    endpoint.state.store(ACTIVE, Ordering::Release);
    if transfer_event || endpoint.port_changes.load(Ordering::Acquire) != 0 {
        softirq::raise(softirq::Slot::UsbInput);
    }
}
fn handler_0() { hard_handler_for(0); } fn handler_1() { hard_handler_for(1); }
fn handler_2() { hard_handler_for(2); } fn handler_3() { hard_handler_for(3); }
fn handler_4() { hard_handler_for(4); } fn handler_5() { hard_handler_for(5); }
fn handler_6() { hard_handler_for(6); } fn handler_7() { hard_handler_for(7); }
const HANDLERS: [fn(); MAX_ENDPOINTS] = [handler_0, handler_1, handler_2, handler_3, handler_4, handler_5, handler_6, handler_7];

fn claim() -> Option<usize> {
    ENDPOINTS.iter().enumerate().find_map(|(index, endpoint)| endpoint.state
        .compare_exchange(FREE, SETUP, Ordering::AcqRel, Ordering::Acquire).ok().map(|_| index))
}
fn release(index: usize) { ENDPOINTS[index].state.store(FREE, Ordering::Release); }

/// Reserve an MSI-X or MSI vector before controller event DMA becomes live. # C: O(N_caps + N_vectors)
pub(crate) fn bind(bdf: pci::Bdf, mmio: &Mmio) -> Option<Binding> {
    let endpoint = claim()?;
    let table = pci_irq::BarMapping { bar: 0, base_va: mmio.base_va(), bytes: mmio.bytes(), offset: 0 };
    let Some(binding) = pci_irq::request(bdf, table, arch_irq::DeviceAction::Xhci, HANDLERS[endpoint]) else {
        release(endpoint);
        return None;
    };
    ENDPOINTS[endpoint].state.store(ACTIVE, Ordering::Release);
    Some(Binding { endpoint, binding })
}

impl Binding {
    /// Publish the retained event page to this vector before controller Run. # C: O(1)
    pub(crate) fn arm(self, mmio: &Mmio, event: &DmaPage) -> bool {
        let Some(intr) = interrupter_offset(mmio.geometry(), 0) else { return false; };
        let Some(event_va) = event.va() else { return false; };
        let endpoint = &ENDPOINTS[self.endpoint];
        endpoint.dequeue.store(0, Ordering::Relaxed);
        endpoint.cycle.store(true, Ordering::Relaxed);
        endpoint.status_offset.store(mmio.geometry().operational + USBSTS, Ordering::Relaxed);
        endpoint.erdp_offset.store(intr + ERDP, Ordering::Relaxed);
        endpoint.event_pa.store(event.dma(), Ordering::Relaxed);
        endpoint.event_va.store(event_va, Ordering::Relaxed);
        endpoint.bar_bytes.store(mmio.bytes(), Ordering::Relaxed);
        endpoint.max_ports.store(mmio.geometry().max_ports, Ordering::Relaxed);
        endpoint.port_changes.store(0, Ordering::Relaxed);
        endpoint.command_completion_pa.store(0, Ordering::Relaxed);
        endpoint.command_completion_status.store(0, Ordering::Relaxed);
        endpoint.transfer_completion_pa.store(0, Ordering::Relaxed);
        endpoint.transfer_completion_meta.store(0, Ordering::Relaxed);
        endpoint.mmio_va.store(mmio.base_va(), Ordering::Release);
        true
    }

    /// Consume a matching Command Completion Event published by this endpoint. # C: O(1)
    pub(crate) fn take_command_completion(self, command_pa: u64) -> Option<crate::ring::CommandCompletion> {
        let endpoint = &ENDPOINTS[self.endpoint];
        if endpoint.command_completion_pa.load(Ordering::Acquire) != command_pa { return None; }
        let status = endpoint.command_completion_status.load(Ordering::Acquire);
        if endpoint.command_completion_pa.compare_exchange(command_pa, 0, Ordering::AcqRel, Ordering::Acquire).is_err() { return None; }
        Some(crate::ring::CommandCompletion { command_pa, completion_code: status as u8, slot: (status >> 8) as u8 })
    }

    /// Wait for one exact command completion without consuming a different command. # C: O(timeout)
    pub(crate) fn wait_command_completion(self, command_pa: u64, timeout_ns: u64) -> Option<crate::ring::CommandCompletion> {
        let deadline = sched::deadline::clock::now_ns().saturating_add(timeout_ns);
        loop {
            if let Some(completion) = self.take_command_completion(command_pa) { return Some(completion); }
            if sched::deadline::clock::now_ns() >= deadline { return None; }
            core::hint::spin_loop();
        }
    }

    /// Consume a matching Transfer Event without losing endpoint or slot identity. # C: O(1)
    pub(crate) fn take_transfer_completion(self, trb_pa: u64) -> Option<crate::ring::TransferCompletion> {
        let endpoint = &ENDPOINTS[self.endpoint];
        if endpoint.transfer_completion_pa.load(Ordering::Acquire) != trb_pa { return None; }
        let meta = endpoint.transfer_completion_meta.load(Ordering::Acquire);
        if endpoint.transfer_completion_pa.compare_exchange(trb_pa, 0, Ordering::AcqRel, Ordering::Acquire).is_err() { return None; }
        Some(crate::ring::TransferCompletion { trb_pa, residual: meta as u32 & 0x00ff_ffff, completion_code: (meta >> 24) as u8, endpoint_id: (meta >> 32) as u8 & 0x1f, slot: (meta >> 40) as u8 })
    }

    /// Consume root-port status changes observed by this controller vector.
    /// # C: O(1)
    pub(crate) fn take_port_changes(self) -> u64 {
        ENDPOINTS[self.endpoint].port_changes.swap(0, Ordering::AcqRel)
    }

    /// Wait for one exact Transfer Event without consuming another endpoint's TD. # C: O(timeout)
    pub(crate) fn wait_transfer_completion(self, trb_pa: u64, timeout_ns: u64) -> Option<crate::ring::TransferCompletion> {
        let deadline = sched::deadline::clock::now_ns().saturating_add(timeout_ns);
        loop {
            if let Some(completion) = self.take_transfer_completion(trb_pa) { return Some(completion); }
            if sched::deadline::clock::now_ns() >= deadline { return None; }
            core::hint::spin_loop();
        }
    }

    /// Disable delivery, wait out hard-handler ownership, then release vector state. # C: O(handler)
    pub(crate) fn disable_and_free(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        loop {
            match endpoint.state.compare_exchange(ACTIVE, SETUP, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) | Err(SETUP) => break,
                Err(HANDLING) => core::hint::spin_loop(),
                Err(_) => break,
            }
        }
        while endpoint.in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
        self.binding.release();
        endpoint.mmio_va.store(0, Ordering::Release);
        endpoint.event_va.store(0, Ordering::Release);
        endpoint.event_pa.store(0, Ordering::Release);
        endpoint.port_changes.store(0, Ordering::Release);
        endpoint.command_completion_pa.store(0, Ordering::Release);
        release(self.endpoint);
    }
}
