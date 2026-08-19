//! Kernel-only owned mappings and DMA pages for one xHCI controller.

use core::ptr::{read_volatile, write_volatile};

use crate::regs::{geometry, protocol_for_port, Geometry, PortProtocol, CAPLENGTH, DBOFF, HCCPARAMS1, HCSPARAMS1, RTSOFF};
use crate::controller::{halt_command, reset_command, reset_complete, USBCMD, USBSTS};
use crate::controller::{RunPlan, CONFIG, CRCR, DCBAAP, ERDP, ERSTBA, ERSTSZ, IMAN};

const PAGE: u64 = 4096;
const LEGACY_CONTROL: u64 = 4;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;
const LEGACY_DISABLE_SMI: u32 = (0x7 << 1) | (0xff << 5) | (0x7 << 17);
const LEGACY_SMI_EVENTS: u32 = 0x7 << 29;
const LEGACY_HANDOFF_NS: u64 = 1_000_000_000;

/// Convert a controller DMA physical page into its direct-map virtual alias.
/// # C: O(1)
fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
}

/// One page of controller-owned, physically contiguous DMA memory.
pub struct DmaPage { bdf: pci::Bdf, pa: u64, dma: u64 }

impl DmaPage {
    /// Byte length of one IOMMU-mapped controller DMA page. # C: O(1)
    pub const BYTES: usize = PAGE as usize;
    /// Allocate and clear a page before it can be named in a controller register.
    /// # C: O(page bytes)
    pub fn allocate(bdf: pci::Bdf, dma_mask: u64) -> Option<Self> {
        let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        let va = hhdm().checked_add(pa)?;
        if va == 0 {
            // SAFETY: this fresh frame never reached a controller-visible pointer.
            unsafe { pmm::setup::free_contig(pa, pmm::Order(0)); }
            return None;
        }
        // SAFETY: `pa` is this page's fresh PMM allocation and no controller can
        // access it before the caller publishes its physical address later.
        unsafe { for byte in 0..PAGE { write_volatile((va + byte) as *mut u8, 0); } }
        let Some(dma) = iommu::map_dma_below(bdf, pa, PAGE as usize, dma_mask) else {
            // SAFETY: no device mapping was published for this fresh PMM allocation.
            unsafe { pmm::setup::free_contig(pa, pmm::Order(0)); }
            return None;
        };
        Some(Self { bdf, pa, dma })
    }

    /// IOMMU-owned device address suitable for 64-byte-aligned xHCI pointers. # C: O(1)
    pub fn dma(&self) -> u64 { self.dma }

    /// Direct-map address for the exclusive controller DMA page. # C: O(1)
    pub fn va(&self) -> Option<u64> { hhdm().checked_add(self.pa) }

    /// Observe controller writes before reading event TRBs. # C: O(page bytes on non-coherent architectures)
    pub fn invalidate_from_device(&self) {
        if let Some(va) = self.va() { pmm::dma::invalidate_from_device(va, PAGE as usize); }
    }

    /// Hand a reusable page to the controller for a device-written transfer.
    ///
    /// A freshly cleared page may still have dirty CPU cache lines on a
    /// non-coherent machine.  Clean those lines before invalidating them so a
    /// later eviction cannot overwrite the controller's reply.
    /// # C: O(page bytes on non-coherent architectures)
    pub fn prepare_for_device_write(&self) {
        if let Some(va) = self.va() {
            pmm::dma::clean_to_device(va, PAGE as usize);
            pmm::dma::invalidate_from_device(va, PAGE as usize);
        }
    }

    /// Write one controller-visible dword within this DMA page. # C: O(1)
    pub fn write32(&self, offset: u64, value: u32) -> bool {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > PAGE) { return false; }
        let Some(va) = hhdm().checked_add(self.pa).and_then(|base| base.checked_add(offset)) else { return false; };
        // SAFETY: this DmaPage owns the direct-map memory and bounds/alignment
        // are checked before the controller has been given a pointer to it.
        unsafe { write_volatile(va as *mut u32, value); }
        true
    }

    /// Write one controller-visible byte within this exclusive DMA page. # C: O(1)
    pub fn write8(&self, offset: u64, value: u8) -> bool {
        if offset >= PAGE { return false; }
        let Some(va) = hhdm().checked_add(self.pa).and_then(|base| base.checked_add(offset)) else { return false; };
        // SAFETY: this DmaPage owns the direct-map memory and the byte offset
        // is checked against its single allocated page before the DMA clean.
        unsafe { write_volatile(va as *mut u8, value); }
        true
    }

    /// Read one controller-written byte from this exclusive DMA page. # C: O(1)
    pub fn read8(&self, offset: u64) -> Option<u8> {
        if offset >= PAGE { return None; }
        let va = hhdm().checked_add(self.pa)?.checked_add(offset)?;
        // SAFETY: this DmaPage exclusively owns the direct-map memory and the
        // offset was checked against its single allocated page.
        Some(unsafe { read_volatile(va as *const u8) })
    }

    /// Read one controller-written dword from this exclusive DMA page. # C: O(1)
    pub fn read32(&self, offset: u64) -> Option<u32> {
        if offset & 3 != 0 || offset.checked_add(4)? > PAGE { return None; }
        let va = hhdm().checked_add(self.pa)?.checked_add(offset)?;
        // SAFETY: this DmaPage exclusively owns the direct-map memory and the
        // offset was checked for dword alignment and page bounds.
        Some(unsafe { read_volatile(va as *const u32) })
    }

    /// Make the completed DMA page visible before its physical address is published.
    /// # C: O(page bytes on non-coherent architectures)
    pub fn clean_to_device(&self) {
        if let Some(va) = hhdm().checked_add(self.pa) {
            pmm::dma::clean_to_device(va, PAGE as usize);
        }
    }
}

impl Drop for DmaPage {
    fn drop(&mut self) {
        if self.pa != 0 {
            if !iommu::unmap_dma(self.bdf, self.dma, PAGE as usize) { return; }
            // SAFETY: DmaPage ownership requires its holder to quiesce the
            // controller before drop; this page is no longer DMA-reachable.
            unsafe { pmm::setup::free_contig(self.pa, pmm::Order(0)); }
            self.pa = 0;
            self.dma = 0;
        }
    }
}

/// Owned BAR0 mapping plus the validated controller register geometry.
pub struct Mmio { mapping: mmio_map::Mapping, geometry: Geometry, bytes: u64 }

impl Mmio {
    /// Map BAR0 and decode its capability block before exposing any registers.
    /// # Safety: `bar_pa..bar_pa+bar_bytes` is the caller-owned xHCI BAR0 range.
    /// # C: O(BAR pages)
    pub unsafe fn map(bar_pa: u64, bar_bytes: u64) -> Option<Self> {
        if bar_pa & (PAGE - 1) != 0 || bar_bytes < PAGE { return None; }
        let pages = bar_bytes.checked_add(PAGE - 1)?.checked_div(PAGE)?;
        // SAFETY: caller proves exclusive ownership of this page-aligned BAR range.
        let mapping = unsafe { mmio_map::map_owned(bar_pa, pages) };
        let base = mapping.base_va();
        // SAFETY: the complete capability-base dword is inside the owned
        // mapping.  Controllers are accessed with dword MMIO transactions;
        // derive both fields exactly as the native host driver does.
        let capbase = unsafe { read_volatile((base + CAPLENGTH) as *const u32) };
        let caplength = capbase as u8;
        let hci_version = (capbase >> 16) as u16;
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let hcsparams1 = unsafe { read_volatile((base + HCSPARAMS1) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let hccparams1 = unsafe { read_volatile((base + HCCPARAMS1) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let dboff = unsafe { read_volatile((base + DBOFF) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let rtsoff = unsafe { read_volatile((base + RTSOFF) as *const u32) };
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  xhci: caps len=");
            klog::write_hex_u64(caplength as u64);
            klog::write_raw(b" ver=");
            klog::write_hex_u64(hci_version as u64);
            klog::write_raw(b" hcs=");
            klog::write_hex_u64(hcsparams1 as u64);
            klog::write_raw(b" hcc=");
            klog::write_hex_u64(hccparams1 as u64);
            klog::write_raw(b" db=");
            klog::write_hex_u64(dboff as u64);
            klog::write_raw(b" rt=");
            klog::write_hex_u64(rtsoff as u64);
            klog::write_raw(b"\n");
        }
        let geometry = geometry(bar_bytes, hci_version, caplength, hcsparams1, hccparams1, dboff, rtsoff)?;
        Some(Self { mapping, geometry, bytes: bar_bytes })
    }

    /// Controller geometry decoded from the live capability registers. # C: O(1)
    pub fn geometry(&self) -> Geometry { self.geometry }

    /// Virtual base of this owned BAR mapping for the registered hard handler. # C: O(1)
    pub fn base_va(&self) -> u64 { self.mapping.base_va() }
    /// Bytes in this owned BAR mapping. # C: O(1)
    pub fn bytes(&self) -> u64 { self.bytes }

    /// Protocol declaration governing one root-hub port, if firmware supplied one. # C: O(BAR dwords)
    pub fn protocol_for_port(&self, port: u8) -> Option<PortProtocol> {
        protocol_for_port(|offset| self.read32(offset), self.bytes, self.geometry.extended_capabilities, self.geometry.max_ports, port)
    }

    /// Take optional firmware ownership of an xHCI controller before reset.
    /// Missing legacy support is valid. A firmware timeout follows the native
    /// driver's forced-takeover rule, then disables legacy SMI delivery.
    /// # C: O(one-second bounded firmware handoff)
    pub fn legacy_handoff(&self, force: bool) -> bool {
        let Some(offset) = crate::regs::legacy_capability_offset(|at| self.read32(at), self.bytes, self.geometry.extended_capabilities) else { return true; };
        let Some(mut legacy) = self.read32(offset) else { return false; };
        if legacy == u32::MAX || offset.checked_add(LEGACY_CONTROL + 4).is_none_or(|end| end > self.bytes) { return false; }
        if force {
            legacy = (legacy | LEGACY_OS_OWNED) & !LEGACY_BIOS_OWNED;
            if !self.write32(offset, legacy) { return false; }
        } else if legacy & LEGACY_BIOS_OWNED != 0 {
            if !self.write32(offset, legacy | LEGACY_OS_OWNED) { return false; }
            let deadline = sched::deadline::clock::now_ns().saturating_add(LEGACY_HANDOFF_NS);
            loop {
                let Some(observed) = self.read32(offset) else { return false; };
                if observed & LEGACY_BIOS_OWNED == 0 { break; }
                if sched::deadline::clock::now_ns() >= deadline {
                    if !self.write32(offset, observed & !LEGACY_BIOS_OWNED) { return false; }
                    break;
                }
                core::hint::spin_loop();
            }
        }
        let Some(control) = self.read32(offset + LEGACY_CONTROL) else { return false; };
        self.write32(offset + LEGACY_CONTROL, (control & LEGACY_DISABLE_SMI) | LEGACY_SMI_EVENTS)
    }

    /// Read one aligned dword that geometry has proven lies in BAR0. # C: O(1)
    pub fn read32(&self, offset: u64) -> Option<u32> {
        if offset & 3 != 0 || offset.checked_add(4)? > self.bytes { return None; }
        // SAFETY: bounds/alignment were validated against this live owned BAR mapping.
        Some(unsafe { read_volatile((self.mapping.base_va() + offset) as *const u32) })
    }

    /// Write one aligned dword that geometry has proven lies in BAR0. # C: O(1)
    pub fn write32(&self, offset: u64, value: u32) -> bool {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bytes) { return false; }
        // SAFETY: bounds/alignment were validated against this live owned BAR mapping.
        unsafe { write_volatile((self.mapping.base_va() + offset) as *mut u32, value); }
        true
    }

    /// Halt then reset this controller, observing both required hardware states.
    /// # C: O(halt timeout + reset timeout)
    pub fn halt_reset(&self) -> bool {
        let op = self.geometry.operational;
        let command = match self.read32(op + USBCMD) { Some(value) => value, None => return false };
        if !self.write32(op + USBCMD, halt_command(command)) { return false; }
        let halt_deadline = sched::deadline::clock::now_ns().saturating_add(16_000_000);
        loop {
            let status = match self.read32(op + USBSTS) { Some(value) => value, None => return false };
            if status & crate::controller::STS_HALT != 0 { break; }
            if sched::deadline::clock::now_ns() >= halt_deadline { return false; }
            core::hint::spin_loop();
        }
        let command = match self.read32(op + USBCMD) { Some(value) => value, None => return false };
        let status = match self.read32(op + USBSTS) { Some(value) => value, None => return false };
        let Some(reset) = reset_command(command, status) else { return false; };
        if !self.write32(op + USBCMD, reset) { return false; }
        let reset_deadline = sched::deadline::clock::now_ns().saturating_add(10_000_000_000);
        loop {
            let command = match self.read32(op + USBCMD) { Some(value) => value, None => return false };
            let status = match self.read32(op + USBSTS) { Some(value) => value, None => return false };
            if reset_complete(command, status) { return true; }
            if sched::deadline::clock::now_ns() >= reset_deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Stop execution and wait until controller DMA has halted. # C: O(halt timeout)
    pub fn halt(&self) -> bool {
        let op = self.geometry.operational;
        let Some(command) = self.read32(op + USBCMD) else { return false; };
        if !self.write32(op + USBCMD, halt_command(command)) { return false; }
        let deadline = sched::deadline::clock::now_ns().saturating_add(16_000_000);
        loop {
            let Some(status) = self.read32(op + USBSTS) else { return false; };
            if status & crate::controller::STS_HALT != 0 { return true; }
            if sched::deadline::clock::now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Start a fully owned controller only after its IRQ/event owner is armed. # C: O(run timeout)
    pub fn run(&self) -> bool {
        let op = self.geometry.operational;
        let Some(command) = self.read32(op + USBCMD) else { return false; };
        if !self.write32(op + USBCMD, crate::controller::run_command(command)) { return false; }
        let deadline = sched::deadline::clock::now_ns().saturating_add(16_000_000);
        loop {
            let Some(status) = self.read32(op + USBSTS) else { return false; };
            if status & crate::controller::STS_HALT == 0 { return status != u32::MAX; }
            if sched::deadline::clock::now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Program all controller DMA pointers while execution remains halted.
    /// # C: O(1)
    pub fn program_halted(&self, plan: RunPlan) -> bool {
        let op = self.geometry.operational;
        let intr = match self.geometry.runtime.checked_add(crate::regs::RUNTIME_INTR0) { Some(value) => value, None => return false };
        self.write64(op + CRCR, plan.crcr)
            && self.write64(op + DCBAAP, plan.dcbaap)
            && self.write32(op + CONFIG, plan.config)
            && self.write32(intr + IMAN, plan.iman)
            && self.write32(intr + ERSTSZ, plan.erstsz)
            && self.write64(intr + ERSTBA, plan.erstba)
            && self.write64(intr + ERDP, plan.erdp)
    }

    fn write64(&self, offset: u64, value: u64) -> bool {
        self.write32(offset, value as u32) && self.write32(offset + 4, (value >> 32) as u32)
    }

    /// Publish ready command-ring TRBs by ringing xHCI doorbell zero. # C: O(1)
    pub fn ring_command_doorbell(&self) -> bool {
        let offset = crate::regs::doorbell_offset(self.geometry, crate::regs::DOORBELL_HOST);
        let Some(offset) = offset else { return false; };
        if !self.write32(offset, 0) { return false; }
        // Readback flushes the posted MMIO write before the caller observes state.
        self.read32(offset).is_some()
    }

    /// Publish ready endpoint TRBs by ringing a slot's endpoint doorbell. # C: O(1)
    pub fn ring_endpoint_doorbell(&self, slot: u8, endpoint_id: u8) -> bool {
        if slot == 0 || slot > self.geometry.max_slots || endpoint_id == 0 || endpoint_id > 31 { return false; }
        let Some(offset) = crate::regs::doorbell_offset(self.geometry, slot) else { return false; };
        if !self.write32(offset, endpoint_id as u32) { return false; }
        self.read32(offset).is_some()
    }

    /// Apply root-hub port power before reset/enumeration. # C: O(1)
    pub fn power_port(&self, port: u8) -> bool {
        let Some(offset) = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes)) else { return false; };
        let Some(portsc) = self.read32(offset) else { return false; };
        portsc & crate::ports::PORT_POWER != 0
            || (self.write32(offset, crate::ports::neutral_portsc(portsc) | crate::ports::PORT_POWER) && self.read32(offset).is_some())
    }

    /// Start USB2 reset; the root-hub worker waits without a controller lock. # C: O(1)
    pub fn request_usb2_reset(&self, port: u8) -> bool {
        let Some(offset) = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes)) else { return false; };
        let Some(portsc) = self.read32(offset) else { return false; };
        let Some(request) = crate::ports::reset_request(portsc) else { return false; };
        self.write32(offset, request)
    }

    /// Read the USB2 reset completion state and clear its one-shot change bit. # C: O(1)
    pub fn finish_usb2_reset(&self, port: u8) -> bool {
        let Some(offset) = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes)) else { return false; };
        let Some(portsc) = self.read32(offset) else { return false; };
        crate::ports::reset_completed(portsc) && self.write32(offset, crate::ports::PORT_RESET_CHANGE)
    }

    /// Acknowledge root-port changes other than USB2 reset completion. # C: O(1)
    pub fn acknowledge_nonreset_changes(&self, port: u8) -> bool {
        let Some(offset) = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes)) else { return false; };
        let Some(portsc) = self.read32(offset) else { return false; };
        let changes = crate::ports::acknowledge_nonreset_changes(portsc);
        changes == 0 || self.write32(offset, changes)
    }

    /// Warm-reset a connected USB3 root-hub port and acknowledge completion. # C: O(reset timeout)
    pub fn reset_usb3_port(&self, port: u8) -> bool {
        let Some(offset) = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes)) else { return false; };
        let Some(portsc) = self.read32(offset) else { return false; };
        if portsc & crate::ports::PORT_CONNECT == 0 || !self.write32(offset, crate::ports::warm_reset_request(portsc)) { return false; }
        let deadline = sched::deadline::clock::now_ns().saturating_add(100_000_000);
        loop {
            let Some(portsc) = self.read32(offset) else { return false; };
            if portsc == u32::MAX { return false; }
            if crate::ports::warm_reset_completed(portsc) {
                return self.write32(offset, crate::ports::PORT_WARM_RESET_CHANGE);
            }
            if sched::deadline::clock::now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Read one validated root-hub PORTSC register. # C: O(1)
    pub fn port_status(&self, port: u8) -> Option<u32> {
        let offset = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)?;
        self.read32(offset)
    }
}
