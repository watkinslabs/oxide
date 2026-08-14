//! AHCI controller-wide ABAR, reset, and port-discovery ownership.

#![cfg(target_os = "oxide-kernel")]

use mmio_map::Mapping;

use crate::port::now_ns;
use crate::regs;

const HBA_RESET_TIMEOUT_NS: u64 = 1_000_000_000;

/// One AHCI PCI function.  The host owns the ABAR mapping and global HBA
/// latches; ports borrow its stable register-file address until host removal.
pub(crate) struct AhciHost {
    bdf: pci::Bdf,
    mmio: Mapping,
    abar_va: u64,
    abar_off: u64,
    cap: u32,
    ports: u32,
}

impl AhciHost {
    /// Reset one HBA, enter AHCI mode, and retain its implemented-port map.
    /// # C: O(reset timeout)
    pub(crate) fn bring_up(bdf: pci::Bdf, mmio: Mapping, abar_off: u64) -> Result<Self, &'static str> {
        let abar_va = mmio.base_va() + abar_off;
        if !Self::enable_ahci_at(abar_va) { return Err("AHCI enable failed"); }
        if !Self::reset_at(abar_va) { return Err("HBA reset timeout"); }
        if !Self::enable_ahci_at(abar_va) { return Err("AHCI enable after reset failed"); }
        let cap = Self::read_at(abar_va, regs::HBA_CAP);
        let ports = regs::usable_port_map(
            cap,
            Self::read_at(abar_va, regs::HBA_PI),
            mmio.bytes().saturating_sub(abar_off),
        );
        if ports == 0 { return Err("no ports implemented"); }
        Ok(Self { bdf, mmio, abar_va, abar_off, cap, ports })
    }

    /// PCI function that owns DMA mappings for all ports. # C: O(1)
    pub(crate) const fn bdf(&self) -> pci::Bdf { self.bdf }
    /// HBA capability bits captured after reset. # C: O(1)
    pub(crate) const fn cap(&self) -> u32 { self.cap }
    /// Implemented AHCI port bitmap. # C: O(1)
    pub(crate) const fn ports(&self) -> u32 { self.ports }
    /// Device mapping address for the shared hard handler. # C: O(1)
    pub(crate) const fn abar_va(&self) -> u64 { self.abar_va }
    /// Complete BAR5 mapping bytes retained by this host. # C: O(1)
    pub(crate) fn abar_map_bytes(&self) -> u64 { self.mmio.bytes() }
    /// BAR5 offset from the owned mapping. # C: O(1)
    pub(crate) const fn abar_offset(&self) -> u64 { self.abar_off }

    /// Read a global or per-port register while this host owns its ABAR. # C: O(1)
    pub(crate) fn r32(&self, off: u64) -> u32 { Self::read_at(self.abar_va, off) }
    /// Write a global or per-port register while this host owns its ABAR. # C: O(1)
    pub(crate) fn w32(&self, off: u64, value: u32) { Self::write_at(self.abar_va, off, value); }

    /// Clear selected port latches, then clear their global level bits. # C: O(N_ports)
    pub(crate) fn clear_interrupts(&self, port_map: u32) {
        for port in 0..32 {
            if port_map & (1 << port) != 0 { self.w32(regs::port_reg(port, regs::P_IS), u32::MAX); }
        }
        self.w32(regs::HBA_IS, port_map);
        let _ = self.r32(regs::HBA_IS);
    }

    /// Enable all supplied port sources then the one host-global IRQ gate. # C: O(N_ports)
    pub(crate) fn enable_interrupts(&self, port_map: u32) {
        self.clear_interrupts(port_map);
        for port in 0..32 {
            if port_map & (1 << port) != 0 { self.w32(regs::port_reg(port, regs::P_IE), regs::PIS_ENABLE); }
        }
        self.w32(regs::HBA_GHC, self.r32(regs::HBA_GHC) | regs::GHC_AE | regs::GHC_IE);
        let _ = self.r32(regs::HBA_GHC);
    }

    /// Mask all port sources and the host-global IRQ gate. # C: O(N_ports)
    pub(crate) fn disable_interrupts(&self, port_map: u32) {
        for port in 0..32 {
            if port_map & (1 << port) != 0 { self.w32(regs::port_reg(port, regs::P_IE), 0); }
        }
        self.w32(regs::HBA_GHC, self.r32(regs::HBA_GHC) & !regs::GHC_IE);
        self.clear_interrupts(port_map);
    }

    /// Mask and acknowledge one port without touching the shared HBA-global
    /// interrupt gate. # C: O(1)
    pub(crate) fn disable_port_interrupts(&self, port: u32) {
        let map = 1u32 << port;
        self.w32(regs::port_reg(port, regs::P_IE), 0);
        let _ = self.r32(regs::port_reg(port, regs::P_IE));
        self.clear_interrupts(map);
    }

    fn read_at(abar_va: u64, off: u64) -> u32 {
        // SAFETY: the caller owns a device mapping covering this aligned AHCI offset.
        unsafe { core::ptr::read_volatile((abar_va + off) as *const u32) }
    }

    fn write_at(abar_va: u64, off: u64, value: u32) {
        // SAFETY: the caller exclusively owns this aligned AHCI register for this HBA.
        unsafe { core::ptr::write_volatile((abar_va + off) as *mut u32, value); }
    }

    fn enable_ahci_at(abar_va: u64) -> bool {
        for _ in 0..5 {
            let ghc = Self::read_at(abar_va, regs::HBA_GHC);
            if ghc & regs::GHC_AE != 0 { return true; }
            Self::write_at(abar_va, regs::HBA_GHC, ghc | regs::GHC_AE);
            if Self::read_at(abar_va, regs::HBA_GHC) & regs::GHC_AE != 0 { return true; }
            let deadline = now_ns().saturating_add(10_000_000);
            while now_ns() < deadline { core::hint::spin_loop(); }
        }
        false
    }

    fn reset_at(abar_va: u64) -> bool {
        let ghc = Self::read_at(abar_va, regs::HBA_GHC);
        if ghc & regs::GHC_HR == 0 {
            Self::write_at(abar_va, regs::HBA_GHC, ghc | regs::GHC_HR);
            let _ = Self::read_at(abar_va, regs::HBA_GHC);
        }
        let deadline = now_ns().saturating_add(HBA_RESET_TIMEOUT_NS);
        loop {
            if Self::read_at(abar_va, regs::HBA_GHC) & regs::GHC_HR == 0 { return true; }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }
}
