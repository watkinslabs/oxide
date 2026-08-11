//! AHCI single-vector MSI-X/MSI binding and allocation-free hard-handler endpoints.

#![cfg(target_os = "oxide-kernel")]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{
    AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering,
};

use crate::port::Ahci;
use crate::regs;

const MAX_ENDPOINTS: usize = 8;
const ENDPOINT_FREE: u8 = 0;
const ENDPOINT_SETUP: u8 = 1;
const ENDPOINT_ACTIVE: u8 = 2;
const ENDPOINT_HANDLING: u8 = 3;
const PCI_RID_BUS_SHIFT: u32 = 8;
const PCI_RID_DEVICE_SHIFT: u32 = 3;

struct Endpoint {
    state:      AtomicU8,
    abar_va:    AtomicU64,
    port:       AtomicU32,
    in_handler: AtomicU32,
    pis:        AtomicU32,
    tfd:        AtomicU32,
    complete:   AtomicBool,
    wake:       AtomicBool,
    irq_count:  AtomicU64,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(ENDPOINT_FREE),
            abar_va: AtomicU64::new(0),
            port: AtomicU32::new(0),
            in_handler: AtomicU32::new(0),
            pis: AtomicU32::new(0),
            tfd: AtomicU32::new(0),
            complete: AtomicBool::new(false),
            wake: AtomicBool::new(false),
            irq_count: AtomicU64::new(0),
        }
    }
}

static ENDPOINTS: [Endpoint; MAX_ENDPOINTS] =
    [const { Endpoint::new() }; MAX_ENDPOINTS];

#[derive(Clone, Copy)]
enum Interrupt { Msi { cap_off: u8 }, Msix { cap_off: u8, entry_va: u64 } }
#[derive(Clone, Copy)]
pub(crate) struct IrqBinding {
    endpoint:      usize,
    irq:           u32,
    bdf:           pci::Bdf,
    interrupt:     Interrupt,
    intx_previous: u16,
}

fn requester_id(bdf: pci::Bdf) -> u32 {
    ((bdf.bus as u32) << PCI_RID_BUS_SHIFT)
        | ((bdf.device as u32) << PCI_RID_DEVICE_SHIFT)
        | bdf.function as u32
}

fn claim_endpoint(ctrl: &Ahci) -> Option<usize> {
    for (idx, endpoint) in ENDPOINTS.iter().enumerate() {
        if endpoint
            .state
            .compare_exchange(
                ENDPOINT_FREE,
                ENDPOINT_SETUP,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            continue;
        }
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

fn bind_msix<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, ctrl: &Ahci) -> Option<IrqBinding> {
    let caps = pci::capabilities(r, bdf);
    let cap_off = caps.find(pci::CAP_ID_MSIX)?.cfg_off;
    let entry_off = regs::msix_entry_offset(pci::decode_msix_cap(r, bdf, cap_off)?, ctrl.abar_map_bytes(), ctrl.abar_offset())?;
    let entry_va = ctrl.abar_va().checked_add(entry_off)?;
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    let Some(endpoint) = claim_endpoint(ctrl) else { arch_irq::free_pci_msi(message.irq); return None; };
    if !arch_irq::register_pci_msi_handler(message.irq, arch_irq::DeviceAction::Ahci, hard_handler) {
        release_endpoint(endpoint); arch_irq::free_pci_msi(message.irq); return None;
    }
    let intx_previous = pci::set_intx_disabled(r, bdf, true);
    if let Some(msi) = caps.find(pci::CAP_ID_MSI) { let _ = pci::disable_msi(r, bdf, msi.cfg_off); }
    let cfg = cap_off & 0xfc;
    r.write32(bdf, cfg, pci::msix_control_enable_masked(r.read32(bdf, cfg)));
    let _ = r.read32(bdf, cfg);
    // SAFETY: `entry_va` is a checked, aligned MSI-X entry inside the controller-owned BAR5 mapping.
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
    ctrl.enable_interrupts();
    Some(IrqBinding { endpoint, irq: message.irq, bdf, interrupt: Interrupt::Msix { cap_off, entry_va }, intx_previous })
}

fn bind_msi<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, ctrl: &Ahci) -> Option<IrqBinding> {
    let cap_off = pci::capabilities(r, bdf).find(pci::CAP_ID_MSI)?.cfg_off;
    let message = arch_irq::alloc_pci_msi(requester_id(bdf), 0)?;
    let endpoint = match claim_endpoint(ctrl) {
        Some(endpoint) => endpoint,
        None => {
            arch_irq::free_pci_msi(message.irq);
            return None;
        }
    };
    if !arch_irq::register_pci_msi_handler(message.irq, arch_irq::DeviceAction::Ahci, hard_handler) {
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
    ENDPOINTS[endpoint]
        .state
        .store(ENDPOINT_ACTIVE, Ordering::Release);
    ctrl.enable_interrupts();
    Some(IrqBinding {
        endpoint,
        irq: message.irq,
        bdf,
        interrupt: Interrupt::Msi { cap_off },
        intx_previous,
    })
}

fn bind_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, ctrl: &Ahci) -> Option<IrqBinding> {
    bind_msix(r, bdf, ctrl).or_else(|| bind_msi(r, bdf, ctrl))
}

/// Bind one single-vector PCI MSI to this AHCI controller. # C: O(N_caps)
pub(crate) fn bind(bdf: pci::Bdf, ctrl: &Ahci) -> Option<IrqBinding> {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::EcamPci::from_published()?;
        bind_with(&r, bdf, ctrl)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let r = hal_aarch64::pci::EcamPci::from_published()?;
        bind_with(&r, bdf, ctrl)
    }
}

fn disable_config_with<R: pci::ConfigSpaceReader>(r: &R, binding: IrqBinding) {
    match binding.interrupt {
        Interrupt::Msi { cap_off } => { let _ = pci::disable_msi(r, binding.bdf, cap_off); }
        Interrupt::Msix { cap_off, entry_va } => {
            // SAFETY: entry VA remains in the controller-owned BAR5 mapping until AHCI teardown finishes.
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
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
        disable_config_with(&r, binding);
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
        disable_config_with(&r, binding);
    }
}

impl IrqBinding {
    /// Reset software completion state before a new doorbell. # C: O(1)
    pub(crate) fn prepare_command(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        endpoint.pis.store(0, Ordering::Release);
        endpoint.tfd.store(0, Ordering::Release);
        endpoint.wake.store(false, Ordering::Release);
        endpoint.complete.store(false, Ordering::Release);
    }

    /// Observe terminal IRQ state for the current command. # C: O(1)
    pub(crate) fn completed(self) -> bool {
        ENDPOINTS[self.endpoint].complete.load(Ordering::Acquire)
    }

    /// Classify the current terminal IRQ state. # C: O(1)
    pub(crate) fn failed(self) -> bool {
        let endpoint = &ENDPOINTS[self.endpoint];
        regs::irq_status_failed(
            endpoint.pis.load(Ordering::Acquire),
            endpoint.tfd.load(Ordering::Acquire),
        )
    }

    /// Consume one hard-handler bottom-half wake request. # C: O(1)
    pub(crate) fn take_wake(self) -> bool {
        ENDPOINTS[self.endpoint].wake.swap(false, Ordering::AcqRel)
    }

    #[cfg(feature = "debug-boot")]
    /// Count terminal IRQ observations. # C: O(1)
    pub(crate) fn completion_count(self) -> u64 {
        ENDPOINTS[self.endpoint].irq_count.load(Ordering::Acquire)
    }

    /// Mask device sources and detach the allocated PCI message. # C: O(N_slots)
    pub(crate) fn mask_and_free(self, ctrl: &Ahci) {
        ctrl.disable_interrupts();
        let endpoint = &ENDPOINTS[self.endpoint];
        loop {
            match endpoint.state.compare_exchange(
                ENDPOINT_ACTIVE,
                ENDPOINT_SETUP,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(ENDPOINT_HANDLING) => core::hint::spin_loop(),
                Err(ENDPOINT_SETUP) => break,
                Err(_) => break,
            }
        }
        disable_config(self);
        arch_irq::free_pci_msi(self.irq);
    }

    /// Wait out a claimed hard endpoint before releasing its MMIO identity. # C: O(handler)
    pub(crate) fn synchronize_and_release(self) {
        let endpoint = &ENDPOINTS[self.endpoint];
        while endpoint.in_handler.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        release_endpoint(self.endpoint);
    }
}

fn hard_handler() {
    let mut raise = false;
    for endpoint in &ENDPOINTS {
        if endpoint
            .state
            .compare_exchange(
                ENDPOINT_ACTIVE,
                ENDPOINT_HANDLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            continue;
        }
        endpoint.in_handler.fetch_add(1, Ordering::AcqRel);
        let abar = endpoint.abar_va.load(Ordering::Acquire);
        let port = endpoint.port.load(Ordering::Acquire);
        let port_bit = 1u32 << port;
        // SAFETY: ACTIVE publishes the driver-owned Device-mapped ABAR and
        // teardown waits for in_handler to drain before unmapping it.
        let hba_is = unsafe {
            core::ptr::read_volatile((abar + regs::HBA_IS) as *const u32)
        };
        if hba_is & port_bit != 0 {
            let port_base = abar + regs::port_off(port);
            // SAFETY: same ACTIVE/in_handler lifetime; offsets are aligned
            // registers within the selected AHCI port block.
            let (pis, ci, tfd) = unsafe {
                (
                    core::ptr::read_volatile((port_base + regs::P_IS) as *const u32),
                    core::ptr::read_volatile((port_base + regs::P_CI) as *const u32),
                    core::ptr::read_volatile((port_base + regs::P_TFD) as *const u32),
                )
            };
            // SAFETY: W1C port causes precede the global level latch, matching
            // Linux `ahci_single_level_irq_intr`.
            unsafe {
                core::ptr::write_volatile((port_base + regs::P_IS) as *mut u32, pis);
                core::ptr::write_volatile((abar + regs::HBA_IS) as *mut u32, hba_is);
            }
            endpoint.pis.fetch_or(pis, Ordering::AcqRel);
            endpoint.tfd.store(tfd, Ordering::Release);
            if regs::irq_finishes_slot(pis, ci, tfd) {
                endpoint.complete.store(true, Ordering::Release);
                endpoint.wake.store(true, Ordering::Release);
                endpoint.irq_count.fetch_add(1, Ordering::Relaxed);
                raise = true;
            }
        }
        endpoint.in_handler.fetch_sub(1, Ordering::Release);
        endpoint.state.store(ENDPOINT_ACTIVE, Ordering::Release);
    }
    if raise { block::completion::raise(); }
}
