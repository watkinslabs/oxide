//! Kernel-only owned mappings and DMA pages for one xHCI controller.

use core::ptr::{read_volatile, write_volatile};

use crate::regs::{geometry, protocol_for_port, Geometry, PortProtocol, CAPLENGTH, DBOFF, HCCPARAMS1, HCSPARAMS1, RTSOFF};
use crate::controller::{halt_command, reset_command, reset_complete, USBCMD, USBSTS};
use crate::controller::{RunPlan, CONFIG, CRCR, DCBAAP, ERDP, ERSTBA, ERSTSZ, IMAN};

const PAGE: u64 = 4096;

/// Convert a controller DMA physical page into its direct-map virtual alias.
/// # C: O(1)
fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
}

/// One page of controller-owned, physically contiguous DMA memory.
pub struct DmaPage { pa: u64 }

impl DmaPage {
    /// Allocate and clear a page before it can be named in a controller register.
    /// # C: O(page bytes)
    pub fn allocate() -> Option<Self> {
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
        Some(Self { pa })
    }

    /// Physical address suitable for 64-byte-aligned xHCI pointers. # C: O(1)
    pub fn pa(&self) -> u64 { self.pa }

    /// Direct-map address for the exclusive controller DMA page. # C: O(1)
    pub fn va(&self) -> Option<u64> { hhdm().checked_add(self.pa) }

    /// Observe controller writes before reading event TRBs. # C: O(page bytes on non-coherent architectures)
    pub fn invalidate_from_device(&self) {
        if let Some(va) = self.va() { pmm::dma::invalidate_from_device(va, PAGE as usize); }
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
            // SAFETY: DmaPage ownership requires its holder to quiesce the
            // controller before drop; this page is no longer DMA-reachable.
            unsafe { pmm::setup::free_contig(self.pa, pmm::Order(0)); }
            self.pa = 0;
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
        // SAFETY: every dword is inside the first capability page of this owned mapping.
        let caplength = unsafe { read_volatile((base + CAPLENGTH) as *const u8) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let hcsparams1 = unsafe { read_volatile((base + HCSPARAMS1) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let hccparams1 = unsafe { read_volatile((base + HCCPARAMS1) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let dboff = unsafe { read_volatile((base + DBOFF) as *const u32) };
        // SAFETY: capability dword access is aligned and inside the owned BAR mapping.
        let rtsoff = unsafe { read_volatile((base + RTSOFF) as *const u32) };
        let geometry = geometry(bar_bytes, caplength, hcsparams1, hccparams1, dboff, rtsoff)?;
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

    /// Reset a connected USB2 root-hub port and acknowledge its reset change. # C: O(reset timeout)
    pub fn reset_usb2_port(&self, port: u8) -> bool {
        let Some(offset) = crate::ports::portsc_offset(self.geometry.operational, port, self.geometry.max_ports)
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes)) else { return false; };
        let Some(portsc) = self.read32(offset) else { return false; };
        let Some(request) = crate::ports::reset_request(portsc) else { return false; };
        if !self.write32(offset, request) { return false; }
        let deadline = sched::deadline::clock::now_ns().saturating_add(100_000_000);
        loop {
            let Some(portsc) = self.read32(offset) else { return false; };
            if portsc == u32::MAX { return false; }
            if crate::ports::reset_completed(portsc) {
                return self.write32(offset, crate::ports::PORT_RESET_CHANGE);
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
