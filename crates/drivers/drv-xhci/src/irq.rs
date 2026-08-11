//! One-vector MSI ownership for a halted xHCI controller.
//!
//! The vector is installed before the controller is allowed to execute.  Event
//! consumption and the Run transition are deliberately a later atomic slice:
//! an enabled controller may not outlive this binding or its DMA pages.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

const MAX_ENDPOINTS: usize = 8;
const FREE: u8 = 0;
const SETUP: u8 = 1;
const ACTIVE: u8 = 2;
const HANDLING: u8 = 3;

struct Endpoint { state: AtomicU8, in_handler: AtomicU32 }
impl Endpoint {
    const fn new() -> Self { Self { state: AtomicU8::new(FREE), in_handler: AtomicU32::new(0) } }
}
static ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [const { Endpoint::new() }; MAX_ENDPOINTS];

#[derive(Clone, Copy)]
pub(crate) struct Binding { endpoint: usize, irq: u32, bdf: pci::Bdf, cap_off: u8, intx_previous: u16 }

fn requester_id(bdf: pci::Bdf) -> u32 { ((bdf.bus as u32) << 8) | ((bdf.device as u32) << 3) | bdf.function as u32 }

fn hard_handler_for(index: usize) {
    let endpoint = &ENDPOINTS[index];
    if endpoint.state.compare_exchange(ACTIVE, HANDLING, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
    // The controller remains halted in this revision, so no xHCI event can be
    // consumed here.  This handler exists solely to establish vector lifetime
    // before the later event-ring dispatcher enables Run.
    endpoint.in_handler.fetch_sub(1, Ordering::Release);
    endpoint.state.store(ACTIVE, Ordering::Release);
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

fn bind_with<R: pci::ConfigSpaceReader>(reader: &R, bdf: pci::Bdf) -> Option<Binding> {
    let cap_off = pci::capabilities(reader, bdf).find(pci::CAP_ID_MSI)?.cfg_off;
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    let Some(endpoint) = claim() else { arch_irq::free_pci_msi(message.irq); return None; };
    if !arch_irq::register_pci_msi_handler(message.irq, arch_irq::DeviceAction::Xhci, HANDLERS[endpoint]) {
        release(endpoint); arch_irq::free_pci_msi(message.irq); return None;
    }
    let intx_previous = pci::set_intx_disabled(reader, bdf, true);
    if !pci::program_msi_single(reader, bdf, cap_off, message.address, message.data) {
        let _ = pci::restore_intx_disabled(reader, bdf, intx_previous);
        arch_irq::free_pci_msi(message.irq); release(endpoint); return None;
    }
    ENDPOINTS[endpoint].state.store(ACTIVE, Ordering::Release);
    Some(Binding { endpoint, irq: message.irq, bdf, cap_off, intx_previous })
}

/// Reserve an MSI vector before the controller can make event DMA live. # C: O(N_caps + N_vectors)
pub(crate) fn bind(bdf: pci::Bdf) -> Option<Binding> {
    #[cfg(target_arch = "x86_64")]
    { bind_with(&hal_x86_64::pci::EcamPci::from_published()?, bdf) }
    #[cfg(target_arch = "aarch64")]
    { bind_with(&hal_aarch64::pci::EcamPci::from_published()?, bdf) }
}

impl Binding {
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
        #[cfg(target_arch = "x86_64")]
        if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() {
            let _ = pci::disable_msi(&reader, self.bdf, self.cap_off);
            let _ = pci::restore_intx_disabled(&reader, self.bdf, self.intx_previous);
        }
        #[cfg(target_arch = "aarch64")]
        if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() {
            let _ = pci::disable_msi(&reader, self.bdf, self.cap_off);
            let _ = pci::restore_intx_disabled(&reader, self.bdf, self.intx_previous);
        }
        arch_irq::free_pci_msi(self.irq);
        while endpoint.in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
        release(self.endpoint);
    }
}
