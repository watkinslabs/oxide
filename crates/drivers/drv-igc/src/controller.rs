//! IGC reset, firmware ownership, and single-queue hardware programming.

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use crate::{dma::Rings, queue::{self, QueuePlan}, regs};

const RESET_QUIESCE_NS: u64 = 10_000_000;
const AUTO_READ_NS: u64 = 10_000_000;

pub struct Controller { map: mmio_map::Mapping, rings: Rings, plan: QueuePlan, rx_next: usize, tx_next: usize, tx_inflight: [bool; queue::RING_COUNT] }

impl Controller {
    /// Creates a controller after reset, firmware handoff, and queue setup.
    /// # C: O(N)
    pub fn bring_up(map: mmio_map::Mapping, bdf: pci::Bdf) -> Option<Self> {
        let rings = Rings::allocate(bdf)?;
        let plan = QueuePlan::new(rings.rx_desc_dma(), rings.tx_desc_dma(), queue::RING_COUNT)?;
        let controller = Self { map, rings, plan, rx_next: 0, tx_next: 0, tx_inflight: [false; queue::RING_COUNT] };
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

    /// Returns the mapped register-file base for the owned PCI interrupt source.
    /// # C: O(1)
    pub fn mmio_base(&self) -> u64 { self.map.base_va() }
    /// Returns the mapped register-file byte extent for PCI MSI-X validation.
    /// # C: O(1)
    pub fn mmio_bytes(&self) -> u64 { self.map.bytes() }
    /// Completes one deferred interrupt poll without losing a masked cause.
    /// # C: O(1)
    pub fn complete_poll(&self) -> bool {
        if self.read(regs::ICR) != 0 { return true; }
        self.write(regs::IMS, regs::IMS_DEFAULT); let _ = self.read(regs::IMS); false
    }

    /// Returns the controller MAC address only when the receive address is valid.
    /// # C: O(1)
    pub fn mac(&self) -> Option<[u8; 6]> {
        let low = self.read(regs::RAL0); let high = self.read(regs::RAH0);
        if high & regs::RAH_AV == 0 { return None; }
        let mac = [low as u8, (low >> 8) as u8, (low >> 16) as u8, (low >> 24) as u8, high as u8, (high >> 8) as u8];
        if mac == [0; 6] || mac == [0xff; 6] { None } else { Some(mac) }
    }

    /// Posts one bounded Ethernet frame to the advanced transmit ring.
    /// # C: O(frame.len())
    pub fn xmit(&mut self, frame: &[u8]) -> Result<(), ()> {
        if !(queue::ETH_MIN_FRAME..=queue::ETH_MAX_FRAME).contains(&frame.len()) { return Err(()); }
        let index = self.tx_next; let desc_va = self.rings.tx_desc_slot_va(index);
        pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<regs::AdvTxWriteback>());
        if self.tx_inflight[index] {
            // SAFETY: the controller lock owns this bounded slot while checking device completion.
            let complete = unsafe { core::ptr::read_volatile(self.rings.tx_desc(index) as *const regs::AdvTxWriteback) };
            if !regs::tx_done(&complete) { return Err(()); }
            self.tx_inflight[index] = false;
        }
        let data_va = self.rings.tx_buffer_va(index);
        // SAFETY: frame bounds were checked against the per-slot DMA buffer and this TX slot is exclusively owned.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), data_va as *mut u8, frame.len()); *self.rings.tx_desc(index) = regs::AdvTxDesc { buffer_addr: self.rings.tx_buffer_dma(index), cmd_type_len: regs::ADVTXD_DTYP_DATA | regs::ADVTXD_DCMD_DEXT | regs::ADVTXD_DCMD_EOP | regs::ADVTXD_DCMD_IFCS | regs::ADVTXD_DCMD_RS | frame.len() as u32, olinfo_status: 0 }; }
        pmm::dma::clean_to_device(data_va, frame.len()); pmm::dma::clean_to_device(desc_va, core::mem::size_of::<regs::AdvTxDesc>());
        fence(Ordering::Release); self.tx_inflight[index] = true; self.tx_next = (index + 1) % queue::RING_COUNT; self.write(regs::TDT0, self.tx_next as u32); Ok(())
    }

    /// Reclaims completed receive descriptors up to the supplied work budget.
    /// # C: O(budget × BUFFER_BYTES)
    pub fn take_rx(&mut self, budget: usize) -> (Vec<Vec<u8>>, bool) {
        let mut frames = Vec::new();
        while frames.len() < budget {
            let index = self.rx_next; let desc_va = self.rings.rx_desc_slot_va(index);
            pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<regs::AdvRxWriteback>()); fence(Ordering::Acquire);
            // SAFETY: the deferred poll owner exclusively consumes this bounded RX descriptor slot.
            let complete = unsafe { core::ptr::read_volatile(self.rings.rx_desc(index) as *const regs::AdvRxWriteback) };
            if !regs::rx_done(&complete) { return (frames, false); }
            let length = complete.length as usize;
            if (queue::ETH_MIN_FRAME..=queue::ETH_MAX_FRAME).contains(&length) {
                let data_va = self.rings.rx_buffer_va(index); pmm::dma::invalidate_from_device(data_va, length);
                // SAFETY: completed descriptor length was checked against the retained per-slot RX buffer.
                frames.push(unsafe { core::slice::from_raw_parts(data_va as *const u8, length) }.to_vec());
            }
            // SAFETY: this completed descriptor is returned to hardware with its original packet-buffer IOVA.
            unsafe { *self.rings.rx_desc(index) = regs::AdvRxDesc { packet_addr: self.rings.rx_buffer_dma(index), header_addr: 0 }; }
            pmm::dma::clean_to_device(desc_va, core::mem::size_of::<regs::AdvRxDesc>()); fence(Ordering::Release);
            self.rx_next = (index + 1) % queue::RING_COUNT; self.write(regs::RDT0, index as u32);
        }
        let desc_va = self.rings.rx_desc_slot_va(self.rx_next); pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<regs::AdvRxWriteback>());
        // SAFETY: rx_next is reduced modulo the ring count and points to a retained descriptor slot.
        let more = unsafe { regs::rx_done(&core::ptr::read_volatile(self.rings.rx_desc(self.rx_next) as *const regs::AdvRxWriteback)) };
        (frames, more)
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
