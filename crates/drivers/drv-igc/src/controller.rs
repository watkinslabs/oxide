//! IGC reset, firmware ownership, and single-queue hardware programming.

use core::sync::atomic::{fence, Ordering};

use crate::{dma::Rings, queue::{self, QueuePlan}, regs};

const RESET_QUIESCE_NS: u64 = 10_000_000;
const AUTO_READ_NS: u64 = 10_000_000;

pub struct Controller { map: mmio_map::Mapping, rings: Rings, plan: QueuePlan }

impl Controller {
    /// Creates a controller after reset, firmware handoff, and queue setup.
    /// # C: O(N)
    pub fn bring_up(map: mmio_map::Mapping, bdf: pci::Bdf) -> Option<Self> {
        let rings = Rings::allocate(bdf)?;
        let plan = QueuePlan::new(rings.rx_desc_dma(), rings.tx_desc_dma(), queue::RING_COUNT)?;
        let controller = Self { map, rings, plan };
        controller.reset(); controller.claim_firmware(); controller.rings.initialize(); controller.program_queues();
        Some(controller)
    }

    /// Enables receive, transmit, and completion causes after queue setup.
    /// # C: O(1)
    pub fn start(&self) {
        self.write(regs::RCTL, regs::RCTL_EN | regs::RCTL_BAM | regs::RCTL_SECRC);
        self.write(regs::TCTL, regs::TCTL_EN | regs::TCTL_PSP);
        let _ = self.read(regs::ICR); self.write(regs::IMS, regs::IMS_DEFAULT); let _ = self.read(regs::IMS);
    }

    /// Stops DMA and masks the interrupt source before mapping release.
    /// # C: O(1)
    pub fn stop(&self) { self.write(regs::IMC, u32::MAX); self.write(regs::RCTL, 0); self.write(regs::TCTL, regs::TCTL_PSP); let _ = self.read(regs::ICR); }

    /// Returns the controller MAC address only when the receive address is valid.
    /// # C: O(1)
    pub fn mac(&self) -> Option<[u8; 6]> {
        let low = self.read(regs::RAL0); let high = self.read(regs::RAH0);
        if high & regs::RAH_AV == 0 { return None; }
        let mac = [low as u8, (low >> 8) as u8, (low >> 16) as u8, (low >> 24) as u8, high as u8, (high >> 8) as u8];
        if mac == [0; 6] || mac == [0xff; 6] { None } else { Some(mac) }
    }

    /// Releases DMA memory and MMIO after caller stopped the device.
    /// # C: O(1)
    pub fn release(mut self) { self.stop(); self.rings.release(); self.map.unmap(); }

    fn reset(&self) {
        self.write(regs::IMC, u32::MAX); self.write(regs::RCTL, 0); self.write(regs::TCTL, regs::TCTL_PSP); let _ = self.read(regs::TCTL);
        let deadline = sched::deadline::clock::now_ns().saturating_add(RESET_QUIESCE_NS);
        while sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
        self.write(regs::CTRL, self.read(regs::CTRL) | regs::CTRL_RST);
        let deadline = sched::deadline::clock::now_ns().saturating_add(AUTO_READ_NS);
        while self.read(regs::EECD) & regs::EECD_AUTO_RD == 0 && sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
        self.write(regs::IMC, u32::MAX); let _ = self.read(regs::ICR);
    }
    fn claim_firmware(&self) { self.write(regs::CTRL_EXT, self.read(regs::CTRL_EXT) | regs::CTRL_EXT_DRV_LOAD); }
    fn program_queues(&self) {
        self.write(regs::RXDCTL0, 0); self.write(regs::RDBAL0, self.plan.rx_dma as u32); self.write(regs::RDBAH0, (self.plan.rx_dma >> 32) as u32); self.write(regs::RDLEN0, self.plan.rx_bytes()); self.write(regs::RDH0, 0); self.write(regs::RDT0, 0);
        self.write(regs::SRRCTL0, self.plan.srrctl(self.read(regs::SRRCTL0))); self.write(regs::RXDCTL0, self.plan.rxdctl());
        self.write(regs::TXDCTL0, 0); let _ = self.read(regs::TXDCTL0); self.write(regs::TDBAL0, self.plan.tx_dma as u32); self.write(regs::TDBAH0, (self.plan.tx_dma >> 32) as u32); self.write(regs::TDLEN0, self.plan.tx_bytes()); self.write(regs::TDH0, 0); self.write(regs::TDT0, 0); self.write(regs::TXDCTL0, self.plan.txdctl());
        fence(Ordering::Release); self.write(regs::RDT0, (queue::RING_COUNT - 1) as u32);
    }
    fn read(&self, offset: u64) -> u32 { // SAFETY: Controller owns the mapped, aligned IGC MMIO register file for its lifetime.
        unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u32) } }
    fn write(&self, offset: u64, value: u32) { // SAFETY: Controller owns the mapped, aligned IGC MMIO register file for its lifetime.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u32, value); } }
}
