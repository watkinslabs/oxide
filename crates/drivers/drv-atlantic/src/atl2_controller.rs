//! AQC113 firmware and one-queue controller lifecycle.

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use crate::{atl2_dma::Rings, atl2_mailbox, atl2_program, atl2_queue::{self as queue, QueuePlan}, atl2_reset};

const RX_BUFFER_ENABLE: u64 = 0x5700;
const TX_BUFFER_ENABLE: u64 = 0x7900;
const BUFFER_ENABLE: u32 = 1;

pub struct Controller { map: mmio_map::Mapping, rings: Rings, plan: QueuePlan, rx_next: usize, tx_next: usize, tx_inflight: [bool; queue::TX_RING_DEFAULT] }

impl Controller {
    /// Resets resident firmware and prepares the default queue without enabling data paths.
    /// # C: O(N)
    pub fn bring_up(map: mmio_map::Mapping, bdf: pci::Bdf, dma_mask: u64) -> Option<Self> {
        let rings = Rings::allocate(bdf, dma_mask)?;
        let plan = QueuePlan::new(rings.rx_desc_dma(), rings.tx_desc_dma(), queue::RX_RING_DEFAULT, queue::TX_RING_DEFAULT)?;
        let mut controller = Self { map, rings, plan, rx_next: 0, tx_next: 0, tx_inflight: [false; queue::TX_RING_DEFAULT] };
        if atl2_reset::reset(&mut controller).is_err() { controller.release(); return None; }
        let filter_caps = match atl2_mailbox::filter_caps(&mut controller) { Ok(caps) => caps, Err(_) => { controller.release(); return None; } };
        if atl2_mailbox::activate(&mut controller).is_err() { controller.release(); return None; }
        let mac = match atl2_mailbox::mac(&mut controller) { Some(mac) => mac, None => { controller.release(); return None; } };
        atl2_program::initialize_paths(&mut controller);
        if crate::atl2_filter::initialize(&mut controller, filter_caps).is_err() { controller.release(); return None; }
        controller.install_mac_filter(mac, filter_caps.l2_filter_slot);
        if atl2_mailbox::set_aqc113_link_speed(&mut controller).is_err() { controller.release(); return None; }
        controller.rings.initialize(); fence(Ordering::Release);
        let plan = controller.plan;
        atl2_program::prepare(&mut controller, plan, (queue::RX_RING_DEFAULT - 1) as u32);
        Some(controller)
    }

    /// Starts queue zero and then enables the global receive and transmit paths.
    /// # C: O(1)
    pub fn start(&mut self) {
        fence(Ordering::Release); let plan = self.plan; atl2_program::start(self, plan);
        self.write32(TX_BUFFER_ENABLE, BUFFER_ENABLE); self.write32(RX_BUFFER_ENABLE, BUFFER_ENABLE);
    }

    /// Programs queue-zero interrupt routing for one MSI/MSI-X vector and unmasks it.
    /// # C: O(1)
    pub fn enable_irq(&mut self, global_control: u32) {
        self.write32(crate::atl2_regs::IRQ_GLOBAL_CONTROL, global_control);
        self.write32(crate::atl2_regs::IRQ_AUTO_MASK, crate::atl2_regs::IRQ_MASK_ALL);
        self.write32(crate::atl2_regs::IRQ_MAP0, crate::atl2_regs::queue_zero_irq_map());
        self.write32(crate::atl2_regs::IRQ_STATUS_CLEAR, crate::atl2_regs::IRQ_MASK_ALL);
        self.write32(crate::atl2_regs::IRQ_MASK_SET, crate::atl2_regs::IRQ_MASK_ALL);
    }

    /// Masks and acknowledges every interrupt cause before controller release.
    /// # C: O(1)
    pub fn disable_irq(&mut self) {
        self.write32(crate::atl2_regs::IRQ_MASK_CLEAR, crate::atl2_regs::IRQ_MASK_ALL);
        self.write32(crate::atl2_regs::IRQ_STATUS_CLEAR, crate::atl2_regs::IRQ_MASK_ALL);
    }

    /// Acknowledges and returns the currently pending interrupt causes.
    /// # C: O(1)
    pub fn irq_status(&mut self) -> u32 {
        let status = self.read32(crate::atl2_regs::IRQ_STATUS);
        if status != 0 { self.write32(crate::atl2_regs::IRQ_STATUS_CLEAR, status); }
        status
    }

    /// Stops global paths and both queue-zero engines before mapping release.
    /// # C: O(1)
    pub fn stop(&mut self) {
        self.disable_irq();
        self.write32(RX_BUFFER_ENABLE, 0); self.write32(TX_BUFFER_ENABLE, 0);
        let rx = crate::atl2_regs::rx_queue_offset(0) + crate::atl2_regs::QUEUE_CONTROL;
        let tx = crate::atl2_regs::tx_queue_offset(0) + crate::atl2_regs::QUEUE_CONTROL;
        let rx_current = self.read32(rx); let tx_current = self.read32(tx);
        self.write32(rx, self.plan.rx_control(rx_current, false)); self.write32(tx, self.plan.tx_control(tx_current, false));
    }

    /// Returns the mapped register-file base for PCI interrupt ownership.
    /// # C: O(1)
    pub fn mmio_base(&self) -> u64 { self.map.base_va() }
    /// Returns the mapped register-file extent for PCI interrupt validation.
    /// # C: O(1)
    pub const fn mmio_bytes(&self) -> u64 { self.map.bytes() }
    /// Returns the firmware-published permanent address when valid.
    /// # C: O(1)
    pub fn mac(&mut self) -> Option<[u8; 6]> { atl2_mailbox::mac(self) }
    /// Installs the permanent address into the firmware-reserved primary L2 slot.
    /// # C: O(1)
    pub fn install_mac_filter(&mut self, mac: [u8; 6], location: u8) {
        let location = location as u64;
        let control = crate::atl2_regs::L2_FILTER_BASE + location * crate::atl2_regs::L2_FILTER_STRIDE + 4;
        let address = control - 4;
        let (low, high) = crate::atl2_regs::l2_filter_mac_words(mac);
        let prior = self.read32(control);
        self.write32(control, prior & !crate::atl2_regs::L2_FILTER_ENABLE);
        self.write32(address, low);
        let next = (prior & !(0xffff | crate::atl2_regs::L2_FILTER_ACTION_MASK | crate::atl2_regs::L2_FILTER_TAG_MASK | crate::atl2_regs::L2_FILTER_ENABLE))
            | high | crate::atl2_regs::L2_FILTER_ACTION_HOST | crate::atl2_regs::L2_FILTER_TAG_UNICAST | crate::atl2_regs::L2_FILTER_ENABLE;
        self.write32(control, next);
    }
    /// Posts one bounded Ethernet frame to queue zero.
    /// # C: O(frame.len())
    pub fn xmit(&mut self, frame: &[u8]) -> Result<(), ()> {
        if !(queue::ETH_MIN_FRAME..=queue::ETH_MAX_FRAME).contains(&frame.len()) { return Err(()); }
        let index = self.tx_next; let desc_va = self.rings.tx_desc_slot_va(index);
        pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<crate::atl2_regs::TxDesc>());
        if self.tx_inflight[index] {
            // SAFETY: controller serialization owns this bounded TX slot while checking completion.
            let complete = unsafe { core::ptr::read_volatile(self.rings.tx_desc(index)) };
            if !crate::atl2_regs::tx_done(&complete) { return Err(()); }
            self.tx_inflight[index] = false;
        }
        let data_va = self.rings.tx_buffer_va(index);
        let control = crate::atl2_regs::tx_data_control(frame.len()).ok_or(())?;
        let control2 = crate::atl2_regs::tx_payload_control(frame.len()).ok_or(())?;
        // SAFETY: frame length was bounded by the private descriptor buffer and the slot is exclusively owned.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), data_va as *mut u8, frame.len()); *self.rings.tx_desc(index) = crate::atl2_regs::TxDesc { buffer_dma: self.rings.tx_buffer_dma(index), control, control2 }; }
        pmm::dma::clean_to_device(data_va, frame.len()); pmm::dma::clean_to_device(desc_va, core::mem::size_of::<crate::atl2_regs::TxDesc>());
        fence(Ordering::Release); self.tx_inflight[index] = true; self.tx_next = (index + 1) % queue::TX_RING_DEFAULT;
        self.write32(crate::atl2_regs::tx_queue_offset(0) + crate::atl2_regs::QUEUE_TAIL, self.tx_next as u32); Ok(())
    }
    /// Reclaims completed receive frames and returns descriptors to queue zero.
    /// # C: O(budget × RX_BUFFER_BYTES)
    pub fn take_rx(&mut self, budget: usize) -> (Vec<Vec<u8>>, bool) {
        let mut frames = Vec::new();
        while frames.len() < budget {
            let index = self.rx_next; let desc_va = self.rings.rx_desc_slot_va(index);
            pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<crate::atl2_regs::RxWriteback>()); fence(Ordering::Acquire);
            // SAFETY: controller serialization exclusively consumes this bounded RX descriptor slot.
            let complete = unsafe { core::ptr::read_volatile(self.rings.rx_desc(index) as *const crate::atl2_regs::RxWriteback) };
            if !crate::atl2_regs::rx_done(&complete) { return (frames, false); }
            let length = complete.length as usize;
            if (queue::ETH_MIN_FRAME..=queue::ETH_MAX_FRAME).contains(&length) {
                let data_va = self.rings.rx_buffer_va(index); pmm::dma::invalidate_from_device(data_va, length);
                // SAFETY: hardware-reported length was bounded by the owned per-slot RX buffer.
                frames.push(unsafe { core::slice::from_raw_parts(data_va as *const u8, length) }.to_vec());
            }
            // SAFETY: completed slot is re-published with the retained RX buffer IOVA.
            unsafe { *self.rings.rx_desc(index) = crate::atl2_regs::RxDesc { buffer_dma: self.rings.rx_buffer_dma(index), header_dma: 0 }; }
            pmm::dma::clean_to_device(desc_va, core::mem::size_of::<crate::atl2_regs::RxDesc>()); fence(Ordering::Release);
            self.rx_next = (index + 1) % queue::RX_RING_DEFAULT;
            self.write32(crate::atl2_regs::rx_queue_offset(0) + crate::atl2_regs::QUEUE_TAIL, self.rx_next as u32);
        }
        let desc_va = self.rings.rx_desc_slot_va(self.rx_next); pmm::dma::invalidate_from_device(desc_va, core::mem::size_of::<crate::atl2_regs::RxWriteback>());
        // SAFETY: rx_next is reduced modulo the ring size and points to an owned descriptor slot.
        let more = unsafe { crate::atl2_regs::rx_done(&core::ptr::read_volatile(self.rings.rx_desc(self.rx_next) as *const crate::atl2_regs::RxWriteback)) };
        (frames, more)
    }
    /// Stops device DMA, releases IOMMU mappings, then unmaps BAR memory.
    /// # C: O(1)
    pub fn release(mut self) { self.stop(); self.rings.release(); self.map.unmap(); }

    fn read32(&mut self, offset: u64) -> u32 {
        // SAFETY: controller owns the aligned MMIO mapping for its complete lifetime.
        unsafe { core::ptr::read_volatile((self.map.base_va() + offset) as *const u32) }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: controller owns the aligned MMIO mapping for its complete lifetime.
        unsafe { core::ptr::write_volatile((self.map.base_va() + offset) as *mut u32, value); }
    }
}

impl atl2_reset::Access for Controller {
    fn read32(&mut self, offset: u64) -> u32 { self.read32(offset) }
    fn write32(&mut self, offset: u64, value: u32) { self.write32(offset, value); }
    fn now_ns(&mut self) -> u64 { sched::deadline::clock::now_ns() }
    fn relax(&mut self) { core::hint::spin_loop(); }
}

impl atl2_mailbox::Access for Controller {
    fn read32(&mut self, offset: u64) -> u32 { self.read32(offset) }
    fn write32(&mut self, offset: u64, value: u32) { self.write32(offset, value); }
    fn now_ns(&mut self) -> u64 { sched::deadline::clock::now_ns() }
    fn relax(&mut self) { core::hint::spin_loop(); }
}

impl atl2_program::Access for Controller {
    fn read32(&mut self, offset: u64) -> u32 { self.read32(offset) }
    fn write32(&mut self, offset: u64, value: u32) { self.write32(offset, value); }
}

impl crate::atl2_filter::Access for Controller {
    fn read32(&mut self, offset: u64) -> u32 { self.read32(offset) }
    fn write32(&mut self, offset: u64, value: u32) { self.write32(offset, value); }
    fn now_ns(&mut self) -> u64 { sched::deadline::clock::now_ns() }
    fn relax(&mut self) { core::hint::spin_loop(); }
}
