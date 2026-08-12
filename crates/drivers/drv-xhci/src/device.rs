//! Retained controller DMA ownership for one Address Device operation.

extern crate alloc;

use alloc::vec::Vec;

use crate::context;
use crate::platform::DmaPage;
use crate::platform::Mmio;
use crate::ring::{CommandRing, Trb, TRB_BYTES, TRBS_PER_SEGMENT};

struct HidDma { ring: DmaPage, report: DmaPage, producer: CommandRing, pending: u64 }

/// Input context, output device context, and endpoint-zero transfer ring.
pub struct AddressDeviceDma { bdf: pci::Bdf, input: DmaPage, output: DmaPage, ep0: DmaPage, descriptor: DmaPage, context_bytes: u8, speed: u8, port: u8, slot: u8, _hid: Option<crate::usb::HidBootInterface>, hid_ring: Option<HidDma>, ep0_ring: CommandRing }

impl AddressDeviceDma {
    /// Allocate and construct every DMA object required by Address Device. # C: O(page bytes)
    pub fn allocate(bdf: pci::Bdf, context_bytes: u8, port: u8, portsc: u32) -> Option<Self> {
        let input = DmaPage::allocate(bdf)?;
        let output = DmaPage::allocate(bdf)?;
        let ep0 = DmaPage::allocate(bdf)?;
        let descriptor = DmaPage::allocate(bdf)?;
        let speed = ((portsc & crate::ports::PORT_SPEED_MASK) >> 10) as u8;
        let words = context::address_device_words(context_bytes, port, portsc, ep0.dma())?;
        for word in words { if !input.write32(word.offset as u64, word.value) { return None; } }
        let link = Trb::link(ep0.dma(), true)?;
        for (word, value) in link.dword.iter().enumerate() {
            if !ep0.write32(((TRBS_PER_SEGMENT - 1) * 16 + word * 4) as u64, *value) { return None; }
        }
        input.clean_to_device(); output.clean_to_device(); ep0.clean_to_device();
        let ep0_ring = CommandRing::new(ep0.dma())?;
        Some(Self { bdf, input, output, ep0, descriptor, context_bytes, speed, port, slot: 0, _hid: None, hid_ring: None, ep0_ring })
    }

    /// Input-context device DMA address for Address Device. # C: O(1)
    pub fn input_pa(&self) -> u64 { self.input.dma() }
    /// Endpoint-zero transfer-ring device DMA address. # C: O(1)
    pub fn ep0_pa(&self) -> u64 { self.ep0.dma() }
    /// DMA address reserved for a standard device descriptor. # C: O(1)
    pub fn descriptor_pa(&self) -> u64 { self.descriptor.dma() }
    /// Read and validate the device descriptor after its completed IN transfer. # C: O(18)
    pub fn device_descriptor(&self) -> Option<crate::usb::DeviceDescriptor> {
        self.descriptor.invalidate_from_device();
        let mut bytes = [0u8; crate::usb::DEVICE_DESC_BYTES];
        for (offset, byte) in bytes.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        crate::usb::device_descriptor(&bytes)
    }
    /// Read the first configuration header after the completed header transfer. # C: O(9)
    pub fn configuration_header(&self) -> Option<crate::usb::ConfigurationHeader> {
        self.descriptor.invalidate_from_device();
        let mut bytes = [0u8; crate::usb::CONFIG_DESC_HEADER_BYTES];
        for (offset, byte) in bytes.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        crate::usb::configuration_header(&bytes)
    }
    /// Parse and retain an eligible HID boot interface from the fetched configuration. # C: O(descriptor bytes)
    pub fn discover_hid_boot(&mut self) -> Option<crate::usb::HidBootInterface> {
        let header = self.configuration_header()?;
        let mut bytes = Vec::with_capacity(header.total_length);
        self.descriptor.invalidate_from_device();
        for offset in 0..header.total_length { bytes.push(self.descriptor.read8(offset as u64)?); }
        let hid = crate::usb::hid_boot_interface(&bytes)?;
        self._hid = Some(hid);
        Some(hid)
    }
    /// Build a retained interrupt-IN ring and Configure Endpoint input context. # C: O(page bytes)
    pub fn prepare_hid_endpoint(&mut self) -> Option<bool> {
        let Some(hid) = self._hid else { return Some(false); };
        let ring = DmaPage::allocate(self.bdf)?;
        let link = Trb::link(ring.dma(), true)?;
        for (word, value) in link.dword.iter().enumerate() {
            if !ring.write32(((TRBS_PER_SEGMENT - 1) * TRB_BYTES + word * 4) as u64, *value) { return None; }
        }
        self.output.invalidate_from_device();
        let stride = self.context_bytes as u64;
        let mut output_slot = [0u32; 8];
        for (index, word) in output_slot.iter_mut().enumerate() { *word = self.output.read32(stride + (index * 4) as u64)?; }
        let words = context::configure_hid_words(self.context_bytes, output_slot, self.speed, hid, ring.dma())?;
        for word in words { if !self.input.write32(word.offset as u64, word.value) { return None; } }
        ring.clean_to_device(); self.input.clean_to_device();
        self.hid_ring = Some(HidDma { producer: CommandRing::new(ring.dma())?, ring, report: DmaPage::allocate(self.bdf)?, pending: 0 });
        Some(true)
    }
    /// Configuration value selected by the discovered HID interface. # C: O(1)
    pub fn hid_configuration(&self) -> Option<u8> { self._hid.map(|hid| hid.configuration) }
    /// Selected HID boot interface descriptor. # C: O(1)
    pub fn hid_interface(&self) -> Option<crate::usb::HidBootInterface> { self._hid }
    /// HID boot protocol: 1 keyboard or 2 mouse. # C: O(1)
    pub fn hid_protocol(&self) -> Option<u8> { self._hid.map(|hid| hid.protocol) }
    /// Enabled xHCI slot retained for this device. # C: O(1)
    pub fn slot(&self) -> u8 { self.slot }
    /// Physical root-hub port this slot was addressed through. # C: O(1)
    pub fn port(&self) -> u8 { self.port }
    /// Publish one HID interrupt-IN report receive TRB and ring that endpoint. # C: O(1)
    pub fn submit_hid_report(&mut self, mmio: &Mmio, slot: u8) -> Option<u64> {
        let hid = self._hid?;
        let endpoint_id = (hid.endpoint & 0x0f).checked_mul(2)?.checked_add(1)?;
        let dma = self.hid_ring.as_mut()?;
        if dma.pending != 0 { return None; }
        let trb = Trb::normal(dma.report.dma(), u32::from(hid.max_packet))?;
        let (pa, _) = dma.producer.push(trb);
        let index = pa.checked_sub(dma.ring.dma())?.checked_div(TRB_BYTES as u64)? as usize;
        let written = dma.producer.trb(index)?;
        for (word, value) in written.dword.iter().enumerate() { if !dma.ring.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; } }
        dma.ring.clean_to_device();
        mmio.ring_endpoint_doorbell(slot, endpoint_id).then_some(pa).inspect(|pending| dma.pending = *pending)
    }
    /// The exact TRB currently owned by the controller for HID input. # C: O(1)
    pub fn hid_pending(&self) -> Option<u64> { self.hid_ring.as_ref().and_then(|dma| (dma.pending != 0).then_some(dma.pending)) }
    /// Consume exactly one successful HID report after its matching Transfer Event. # C: O(report bytes)
    pub fn take_hid_report(&mut self, completion: crate::ring::TransferCompletion) -> Option<Vec<u8>> {
        let hid = self._hid?;
        let endpoint_id = (hid.endpoint & 0x0f).checked_mul(2)?.checked_add(1)?;
        let dma = self.hid_ring.as_mut()?;
        if completion.trb_pa != dma.pending || completion.completion_code != crate::ring::COMPLETION_SUCCESS || completion.endpoint_id != endpoint_id || completion.residual > u32::from(hid.max_packet) { return None; }
        dma.pending = 0;
        dma.report.invalidate_from_device();
        let length = usize::from(hid.max_packet) - completion.residual as usize;
        let mut report = Vec::with_capacity(length);
        for offset in 0..length { report.push(dma.report.read8(offset as u64)?); }
        Some(report)
    }
    /// Rebuild the input context from controller output for Linux's EP0 MPS update. # C: O(1)
    pub fn prepare_evaluate_ep0(&self, max_packet: u8) -> Option<bool> {
        let stride = self.context_bytes as u64;
        let ep0 = 2 * stride;
        self.output.invalidate_from_device();
        let mut output_ep0 = [0u32; 5];
        for (index, word) in output_ep0.iter_mut().enumerate() { *word = self.output.read32(ep0 + (index * 4) as u64)?; }
        if ((output_ep0[1] >> 16) & 0xffff) as u8 == max_packet { return Some(false); }
        let words = context::evaluate_ep0_words(self.context_bytes, output_ep0, max_packet)?;
        for word in words { if !self.input.write32(word.offset as u64, word.value) { return None; } }
        self.input.clean_to_device();
        Some(true)
    }
    /// Publish one complete EP0 control-transfer TD and ring endpoint zero. # C: O(TRBs)
    pub fn submit_ep0(&mut self, mmio: &Mmio, slot: u8, trbs: &[Trb]) -> Option<u64> {
        if !(2..=3).contains(&trbs.len()) { return None; }
        let mut completion = 0;
        for trb in trbs {
            let (pa, _) = self.ep0_ring.push(*trb);
            let index = pa.checked_sub(self.ep0.dma())?.checked_div(TRB_BYTES as u64)? as usize;
            let written = self.ep0_ring.trb(index)?;
            for (word, value) in written.dword.iter().enumerate() {
                if !self.ep0.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; }
            }
            completion = pa;
        }
        self.ep0.clean_to_device();
        mmio.ring_endpoint_doorbell(slot, 1).then_some(completion)
    }
    /// Publish the output device context in a valid nonzero DCBAA slot. # C: O(1)
    pub fn publish_dcbaa(&mut self, dcbaa: &DmaPage, slot: u8) -> bool {
        if slot == 0 || (slot as usize) * 8 + 8 > 4096 { return false; }
        let offset = slot as u64 * 8;
        if !dcbaa.write32(offset, self.output.dma() as u32) || !dcbaa.write32(offset + 4, (self.output.dma() >> 32) as u32) { return false; }
        dcbaa.clean_to_device();
        self.slot = slot;
        true
    }
}
