//! Retained controller DMA ownership for one Address Device operation.

extern crate alloc;

use alloc::vec::Vec;

use crate::context;
use crate::platform::DmaPage;
use crate::platform::Mmio;
use crate::ring::{CommandRing, Trb, TRB_BYTES, TRBS_PER_SEGMENT};

struct HidDma { ring: DmaPage, report: DmaPage, producer: CommandRing, pending: u64 }
struct HubDma { ring: DmaPage, status: DmaPage, producer: CommandRing, pending: u64 }

struct StorageDma {
    bulk_in_ring: DmaPage, bulk_out_ring: DmaPage, command: DmaPage, status: DmaPage, data: Vec<DmaPage>,
    bulk_in_producer: CommandRing, bulk_out_producer: CommandRing,
}

/// Input context, output device context, and endpoint-zero transfer ring.
pub struct AddressDeviceDma { bdf: pci::Bdf, dma_mask: u64, input: DmaPage, output: DmaPage, ep0: DmaPage, descriptor: DmaPage, context_bytes: u8, speed: u8, topology: crate::context::DeviceTopology, slot: u8, device_protocol: u8, hub_descriptor: Option<crate::usb::HubDescriptor>, hub_needs_power: bool, hub_events: [u8; crate::usb::HUB_STATUS_MAX_BYTES], hub_events_len: u8, _hid: Option<crate::usb::HidInterface>, hid_layout: Option<crate::hid_report::ReportLayout>, _hub: Option<crate::usb::HubInterface>, _storage: Option<crate::storage::MassStorageInterface>, hid_ring: Option<HidDma>, hub_ring: Option<HubDma>, storage_dma: Option<StorageDma>, ep0_ring: CommandRing }

/// Maximum chained USB-storage transfer accepted by one retained endpoint ring.
pub const STORAGE_MAX_TRANSFER_BYTES: usize = DmaPage::BYTES * crate::ring::COMMAND_USABLE_TRBS;

impl AddressDeviceDma {
    /// Allocate and construct every DMA object required by Address Device. # C: O(page bytes)
    pub fn allocate(bdf: pci::Bdf, context_bytes: u8, dma_mask: u64, port: u8, portsc: u32) -> Option<Self> {
        Self::allocate_topology(bdf, context_bytes, dma_mask, crate::context::DeviceTopology::root(port)?, portsc)
    }

    /// Allocate one device below a normalized xHCI root/hub topology.
    /// # C: O(page bytes)
    pub fn allocate_topology(bdf: pci::Bdf, context_bytes: u8, dma_mask: u64, topology: crate::context::DeviceTopology, portsc: u32) -> Option<Self> {
        let input = DmaPage::allocate(bdf, dma_mask)?;
        let output = DmaPage::allocate(bdf, dma_mask)?;
        let ep0 = DmaPage::allocate(bdf, dma_mask)?;
        let descriptor = DmaPage::allocate(bdf, dma_mask)?;
        let speed = ((portsc & crate::ports::PORT_SPEED_MASK) >> 10) as u8;
        let words = context::address_device_topology_words(context_bytes, topology, portsc, ep0.dma())?;
        for word in words { if !input.write32(word.offset as u64, word.value) { return None; } }
        let link = Trb::link(ep0.dma(), true)?;
        for (word, value) in link.dword.iter().enumerate() {
            if !ep0.write32(((TRBS_PER_SEGMENT - 1) * 16 + word * 4) as u64, *value) { return None; }
        }
        input.clean_to_device(); output.clean_to_device(); ep0.clean_to_device();
        let ep0_ring = CommandRing::new(ep0.dma())?;
        Some(Self { bdf, dma_mask, input, output, ep0, descriptor, context_bytes, speed, topology, slot: 0, device_protocol: 0, hub_descriptor: None, hub_needs_power: false, hub_events: [0; crate::usb::HUB_STATUS_MAX_BYTES], hub_events_len: 0, _hid: None, hid_layout: None, _hub: None, _storage: None, hid_ring: None, hub_ring: None, storage_dma: None, ep0_ring })
    }

    /// Input-context device DMA address for Address Device. # C: O(1)
    pub fn input_pa(&self) -> u64 { self.input.dma() }
    /// Endpoint-zero transfer-ring device DMA address. # C: O(1)
    pub fn ep0_pa(&self) -> u64 { self.ep0.dma() }
    /// DMA address reserved for a standard device descriptor. # C: O(1)
    pub fn descriptor_pa(&self) -> u64 { self.descriptor.dma() }
    /// Read and validate the device descriptor after its completed IN transfer. # C: O(18)
    pub fn device_descriptor(&mut self) -> Option<crate::usb::DeviceDescriptor> {
        self.descriptor.invalidate_from_device();
        let mut bytes = [0u8; crate::usb::DEVICE_DESC_BYTES];
        for (offset, byte) in bytes.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        let descriptor = crate::usb::device_descriptor(&bytes)?;
        self.device_protocol = descriptor.device_protocol;
        Some(descriptor)
    }
    /// Read the first configuration header after the completed header transfer. # C: O(9)
    pub fn configuration_header(&self) -> Option<crate::usb::ConfigurationHeader> {
        self.descriptor.invalidate_from_device();
        let mut bytes = [0u8; crate::usb::CONFIG_DESC_HEADER_BYTES];
        for (offset, byte) in bytes.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        crate::usb::configuration_header(&bytes)
    }
    /// Parse and retain one descriptor-selected HID interrupt interface. # C: O(descriptor bytes)
    pub fn discover_hid(&mut self) -> Option<crate::usb::HidInterface> {
        let hid = crate::usb::hid_interface(&self.configuration_bytes()?)?;
        self._hid = Some(hid);
        Some(hid)
    }
    /// Parse and retain a transparent-SCSI Bulk-Only interface from the fetched configuration. # C: O(descriptor bytes)
    pub fn discover_mass_storage(&mut self) -> Option<crate::storage::MassStorageInterface> {
        let storage = crate::usb::mass_storage_interface(&self.configuration_bytes()?)?;
        self._storage = Some(storage);
        Some(storage)
    }
    /// Parse and retain a hub status-change endpoint. # C: O(descriptor bytes)
    pub fn discover_hub(&mut self) -> Option<crate::usb::HubInterface> {
        let hub = crate::usb::hub_interface(&self.configuration_bytes()?)?;
        self._hub = Some(hub); Some(hub)
    }
    /// Build a retained interrupt-IN ring and Configure Endpoint input context. # C: O(page bytes)
    pub fn prepare_hid_endpoint(&mut self) -> Option<bool> {
        let Some(hid) = self._hid else { return Some(false); };
        let ring = DmaPage::allocate(self.bdf, self.dma_mask)?;
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
        self.hid_ring = Some(HidDma { producer: CommandRing::new(ring.dma())?, ring, report: DmaPage::allocate(self.bdf, self.dma_mask)?, pending: 0 });
        Some(true)
    }
    /// Retain the hub status ring and configure its interrupt-IN endpoint. # C: O(page bytes)
    pub fn prepare_hub_endpoint(&mut self) -> Option<bool> {
        let Some(hub) = self._hub else { return Some(false); };
        let (ring, producer) = transfer_ring(self.bdf, self.dma_mask)?;
        self.output.invalidate_from_device();
        let stride = self.context_bytes as u64;
        let mut output_slot = [0u32; 8];
        for (index, word) in output_slot.iter_mut().enumerate() { *word = self.output.read32(stride + (index * 4) as u64)?; }
        let words = context::configure_hub_words(self.context_bytes, output_slot, self.speed, hub, ring.dma())?;
        for word in words { if !self.input.write32(word.offset as u64, word.value) { return None; } }
        ring.clean_to_device(); self.input.clean_to_device();
        self.hub_ring = Some(HubDma { ring, status: DmaPage::allocate(self.bdf, self.dma_mask)?, producer, pending: 0 }); Some(true)
    }
    /// Retain bulk rings and DMA buffers, then populate their Configure Endpoint input contexts. # C: O(page bytes)
    pub fn prepare_storage_endpoints(&mut self) -> Option<bool> {
        let Some(storage) = self._storage else { return Some(false); };
        if self.storage_dma.is_some() { return Some(true); }
        let (bulk_in_ring, bulk_in_producer) = transfer_ring(self.bdf, self.dma_mask)?;
        let (bulk_out_ring, bulk_out_producer) = transfer_ring(self.bdf, self.dma_mask)?;
        self.output.invalidate_from_device();
        let stride = self.context_bytes as u64;
        let mut output_slot = [0u32; 8];
        for (index, word) in output_slot.iter_mut().enumerate() { *word = self.output.read32(stride + (index * 4) as u64)?; }
        let words = context::configure_storage_words(self.context_bytes, output_slot, self.speed, storage, bulk_in_ring.dma(), bulk_out_ring.dma())?;
        for word in words { if !self.input.write32(word.offset as u64, word.value) { return None; } }
        self.input.clean_to_device();
        self.storage_dma = Some(StorageDma {
            bulk_in_ring, bulk_out_ring, command: DmaPage::allocate(self.bdf, self.dma_mask)?, status: DmaPage::allocate(self.bdf, self.dma_mask)?, data: Vec::new(), bulk_in_producer, bulk_out_producer,
        });
        Some(true)
    }
    /// Configuration value selected by the discovered HID interface. # C: O(1)
    pub fn hid_configuration(&self) -> Option<u8> { self._hid.map(|hid| hid.configuration) }
    /// Configuration value selected by the discovered hub interface. # C: O(1)
    pub fn hub_configuration(&self) -> Option<u8> { self._hub.map(|hub| hub.configuration) }
    /// Configuration value selected by the discovered mass-storage interface. # C: O(1)
    pub fn storage_configuration(&self) -> Option<u8> { self._storage.map(|storage| storage.configuration) }
    /// Selected transparent-SCSI Bulk-Only interface descriptor. # C: O(1)
    pub fn storage_interface(&self) -> Option<crate::storage::MassStorageInterface> { self._storage }
    /// Selected descriptor-driven HID interface descriptor. # C: O(1)
    pub fn hid_interface(&self) -> Option<crate::usb::HidInterface> { self._hid }
    /// Parse and retain the exact report descriptor completed in the descriptor page. # C: O(report bytes)
    pub fn discover_hid_report(&mut self) -> Option<crate::hid_report::ReportLayout> {
        let hid = self._hid?;
        self.descriptor.invalidate_from_device();
        let mut bytes = Vec::with_capacity(hid.report_bytes);
        for offset in 0..hid.report_bytes { bytes.push(self.descriptor.read8(offset as u64)?); }
        let layout = crate::hid_report::parse_report_descriptor(&bytes)?;
        self.hid_layout = Some(layout);
        Some(layout)
    }
    /// Validated descriptor-driven HID input layout. # C: O(1)
    pub fn hid_layout(&self) -> Option<crate::hid_report::ReportLayout> { self.hid_layout }
    /// Selected hub interface descriptor. # C: O(1)
    pub fn hub_interface(&self) -> Option<crate::usb::HubInterface> { self._hub }
    /// Retained hub descriptor used to bound downstream-port control. # C: O(1)
    pub fn hub_descriptor(&self) -> Option<crate::usb::HubDescriptor> { self.hub_descriptor }
    /// Read the exact hub-descriptor size after its fixed-header transfer. # C: O(7)
    pub fn hub_descriptor_length(&self) -> Option<usize> {
        self.descriptor.invalidate_from_device();
        let mut header = [0u8; crate::usb::HUB_DESC_HEADER_BYTES];
        for (offset, byte) in header.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        crate::usb::hub_descriptor_length(&header)
    }
    /// Submit a hub-port GET_STATUS control transfer into the retained descriptor page. # C: O(1)
    pub fn submit_hub_port_status(&mut self, mmio: &Mmio, slot: u8, port: u8) -> Option<u64> {
        let td = crate::usb::get_hub_port_status_trbs(self.descriptor.dma(), port)?;
        self.submit_ep0(mmio, slot, &td)
    }
    /// Decode the retained hub-port GET_STATUS reply after its exact completion. # C: O(4)
    pub fn hub_port_status(&self) -> Option<crate::usb::HubPortStatus> {
        self.descriptor.invalidate_from_device();
        let mut bytes = [0u8; crate::usb::HUB_PORT_STATUS_BYTES];
        for (offset, byte) in bytes.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        crate::usb::hub_port_status(&bytes)
    }
    /// Submit one class-port SET_FEATURE or CLEAR_FEATURE control transfer. # C: O(1)
    pub fn submit_hub_port_feature(&mut self, mmio: &Mmio, slot: u8, port: u8, feature: u16, set: bool) -> Option<u64> {
        let td = crate::usb::hub_port_feature_trbs(port, feature, set)?;
        self.submit_ep0(mmio, slot, &td)
    }
    /// Read and retain a complete hub descriptor after its EP0 control transfer. # C: O(descriptor bytes)
    pub fn discover_hub_descriptor(&mut self) -> Option<crate::usb::HubDescriptor> {
        self.descriptor.invalidate_from_device();
        let mut header = [0u8; crate::usb::HUB_DESC_HEADER_BYTES];
        for (offset, byte) in header.iter_mut().enumerate() { *byte = self.descriptor.read8(offset as u64)?; }
        let length = crate::usb::hub_descriptor_length(&header)?;
        let mut bytes = Vec::with_capacity(length);
        for offset in 0..length { bytes.push(self.descriptor.read8(offset as u64)?); }
        let descriptor = crate::usb::hub_descriptor(&bytes)?;
        self.hub_descriptor = Some(descriptor);
        self.hub_needs_power = true;
        let length = (usize::from(descriptor.ports).checked_add(8)? / 8).max(1);
        for port in 1..=descriptor.ports {
            let bit = usize::from(port);
            self.hub_events[bit / 8] |= 1 << (bit % 8);
        }
        self.hub_events_len = length as u8;
        Some(descriptor)
    }
    /// Build the controller input context that identifies this slot as a hub. # C: O(1)
    pub fn prepare_hub_slot(&mut self, hci_version: u16) -> Option<bool> {
        let hub = self.hub_descriptor?;
        self.output.invalidate_from_device();
        let stride = self.context_bytes as u64;
        let mut output_slot = [0u32; 8];
        for (index, word) in output_slot.iter_mut().enumerate() { *word = self.output.read32(stride + (index * 4) as u64)?; }
        let words = context::update_hub_slot_words(self.context_bytes, output_slot, hci_version, self.speed, self.device_protocol, hub)?;
        for word in words { if !self.input.write32(word.offset as u64, word.value) { return None; } }
        self.input.clean_to_device();
        Some(true)
    }
    /// Publish the command-block wrapper for one Bulk-Only command. # C: O(CBW bytes)
    pub fn submit_storage_cbw(&mut self, mmio: &Mmio, slot: u8, tag: u32, transfer_bytes: u32, device_to_host: bool, cdb: &[u8]) -> Option<u64> {
        let storage = self._storage?;
        let dma = self.storage_dma.as_mut()?;
        let cbw = crate::storage::command_block(tag, transfer_bytes, device_to_host, 0, cdb)?;
        for (offset, byte) in cbw.into_iter().enumerate() { if !dma.command.write8(offset as u64, byte) { return None; } }
        dma.command.clean_to_device();
        submit_transfer(mmio, slot, storage.bulk_out, &mut dma.bulk_out_producer, &dma.bulk_out_ring, dma.command.dma(), crate::storage::CBW_BYTES as u32)
    }
    /// Publish the data stage for a Bulk-Only command. # C: O(data bytes)
    pub fn submit_storage_data(&mut self, mmio: &Mmio, slot: u8, length: u32, device_to_host: bool) -> Option<u64> {
        let storage = self._storage?;
        let dma = self.storage_dma.as_mut()?;
        if length == 0 || length as usize > STORAGE_MAX_TRANSFER_BYTES { return None; }
        ensure_storage_pages(self.bdf, self.dma_mask, &mut dma.data, length as usize)?;
        let (endpoint, producer, ring) = if device_to_host { (storage.bulk_in, &mut dma.bulk_in_producer, &dma.bulk_in_ring) } else { (storage.bulk_out, &mut dma.bulk_out_producer, &dma.bulk_out_ring) };
        submit_transfer_pages(mmio, slot, endpoint, producer, ring, &dma.data, length as usize)
    }
    /// Publish the final IN command-status wrapper receive. # C: O(CSW bytes)
    pub fn submit_storage_csw(&mut self, mmio: &Mmio, slot: u8) -> Option<u64> {
        let storage = self._storage?;
        let dma = self.storage_dma.as_mut()?;
        submit_transfer(mmio, slot, storage.bulk_in, &mut dma.bulk_in_producer, &dma.bulk_in_ring, dma.status.dma(), crate::storage::CSW_BYTES as u32)
    }
    /// Read a completed data-stage payload after its matching IN completion. # C: O(data bytes)
    pub fn storage_data(&self, length: usize) -> Option<Vec<u8>> {
        if length > STORAGE_MAX_TRANSFER_BYTES { return None; }
        let dma = self.storage_dma.as_ref()?;
        let page_count = pages_for(length)?;
        if page_count > dma.data.len() { return None; }
        for page in dma.data.iter().take(page_count) { page.invalidate_from_device(); }
        let mut bytes = Vec::with_capacity(length);
        for offset in 0..length {
            let page = offset / DmaPage::BYTES;
            bytes.push(dma.data[page].read8((offset % DmaPage::BYTES) as u64)?);
        }
        Some(bytes)
    }
    /// Copy one host-to-device Bulk-Only data stage into its retained DMA page.
    /// # C: O(data bytes)
    pub fn set_storage_data(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > STORAGE_MAX_TRANSFER_BYTES { return false; }
        let Some(dma) = self.storage_dma.as_mut() else { return false; };
        if ensure_storage_pages(self.bdf, self.dma_mask, &mut dma.data, bytes.len()).is_none() { return false; }
        for (offset, byte) in bytes.iter().copied().enumerate() {
            let page = offset / DmaPage::BYTES;
            if !dma.data[page].write8((offset % DmaPage::BYTES) as u64, byte) { return false; }
        }
        for page in dma.data.iter().take(pages_for(bytes.len()).unwrap_or(0)) { page.clean_to_device(); }
        true
    }
    /// Read and validate a completed Bulk-Only command-status wrapper. # C: O(CSW bytes)
    pub fn storage_csw(&self, tag: u32, transfer_bytes: u32) -> Option<(crate::storage::CswStatus, u32)> {
        let dma = self.storage_dma.as_ref()?;
        dma.status.invalidate_from_device();
        let mut bytes = [0u8; crate::storage::CSW_BYTES];
        for (offset, byte) in bytes.iter_mut().enumerate() { *byte = dma.status.read8(offset as u64)?; }
        crate::storage::command_status(&bytes, tag, transfer_bytes)
    }
    /// Enabled xHCI slot retained for this device. # C: O(1)
    pub fn slot(&self) -> u8 { self.slot }
    /// Physical root-hub port this slot was addressed through. # C: O(1)
    pub fn port(&self) -> u8 { self.topology.root_port }
    /// xHCI root-port plus route-string identity of this device. # C: O(1)
    pub fn topology(&self) -> crate::context::DeviceTopology { self.topology }
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
    /// Publish one hub status-change bitmap receive and ring its interrupt endpoint. # C: O(1)
    pub fn submit_hub_status(&mut self, mmio: &Mmio, slot: u8) -> Option<u64> {
        let hub = self._hub?;
        if usize::from(hub.max_packet) > DmaPage::BYTES { return None; }
        let endpoint_id = (hub.endpoint & 0x0f).checked_mul(2)?.checked_add(1)?;
        let dma = self.hub_ring.as_mut()?;
        if dma.pending != 0 { return None; }
        let trb = Trb::normal(dma.status.dma(), u32::from(hub.max_packet))?;
        let (pa, _) = dma.producer.push(trb);
        let index = pa.checked_sub(dma.ring.dma())?.checked_div(TRB_BYTES as u64)? as usize;
        let written = dma.producer.trb(index)?;
        for (word, value) in written.dword.iter().enumerate() { if !dma.ring.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; } }
        dma.ring.clean_to_device();
        mmio.ring_endpoint_doorbell(slot, endpoint_id).then_some(pa).inspect(|pending| dma.pending = *pending)
    }
    /// The exact TRB currently owned by the controller for HID input. # C: O(1)
    pub fn hid_pending(&self) -> Option<u64> { self.hid_ring.as_ref().and_then(|dma| (dma.pending != 0).then_some(dma.pending)) }
    /// The exact TRB currently owned by the controller for hub status input. # C: O(1)
    pub fn hub_pending(&self) -> Option<u64> { self.hub_ring.as_ref().and_then(|dma| (dma.pending != 0).then_some(dma.pending)) }
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
    /// Consume one completed hub status bitmap after its matching Transfer Event. # C: O(status bytes)
    pub fn take_hub_status(&mut self, completion: crate::ring::TransferCompletion) -> Option<()> {
        let hub = self._hub?;
        let descriptor = self.hub_descriptor?;
        let endpoint_id = (hub.endpoint & 0x0f).checked_mul(2)?.checked_add(1)?;
        let dma = self.hub_ring.as_mut()?;
        if completion.trb_pa != dma.pending || completion.completion_code != crate::ring::COMPLETION_SUCCESS || completion.endpoint_id != endpoint_id || completion.residual > u32::from(hub.max_packet) { return None; }
        dma.pending = 0;
        dma.status.invalidate_from_device();
        let length = usize::from(hub.max_packet).checked_sub(completion.residual as usize)?;
        let expected = (usize::from(descriptor.ports).checked_add(8)? / 8).max(1);
        if length != expected { return None; }
        let mut bytes = [0u8; crate::usb::HUB_STATUS_MAX_BYTES];
        for (offset, byte) in bytes.iter_mut().take(length).enumerate() { *byte = dma.status.read8(offset as u64)?; }
        let bitmap = crate::usb::hub_status_bitmap(&bytes[..length], descriptor.ports)?;
        for (saved, changed) in self.hub_events.iter_mut().zip(bitmap.bytes()) { *saved |= changed; }
        self.hub_events_len = self.hub_events_len.max(bitmap.bytes().len() as u8);
        Some(())
    }
    /// Claim all coalesced hub-status event bits for process-context service. # C: O(status bytes)
    pub fn take_hub_events(&mut self) -> Option<crate::usb::HubStatusBitmap> {
        let ports = self.hub_descriptor?.ports;
        let length = usize::from(self.hub_events_len);
        if length == 0 { return None; }
        let bitmap = crate::usb::hub_status_bitmap(&self.hub_events[..length], ports)?;
        self.hub_events[..length].fill(0);
        self.hub_events_len = 0;
        Some(bitmap)
    }
    /// Claim initial hub-port power-up delay once after descriptor discovery. # C: O(1)
    pub fn take_hub_power_delay_ms(&mut self) -> Option<u16> {
        let hub = self.hub_descriptor?;
        if !self.hub_needs_power { return None; }
        self.hub_needs_power = false;
        Some(hub.power_good_ms)
    }
    /// Whether an interrupt status bitmap still awaits process-context service. # C: O(1)
    pub fn hub_events_pending(&self) -> bool { self.hub_events_len != 0 }
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

    fn configuration_bytes(&self) -> Option<Vec<u8>> {
        let header = self.configuration_header()?;
        let mut bytes = Vec::with_capacity(header.total_length);
        self.descriptor.invalidate_from_device();
        for offset in 0..header.total_length { bytes.push(self.descriptor.read8(offset as u64)?); }
        Some(bytes)
    }
}

fn transfer_ring(bdf: pci::Bdf, dma_mask: u64) -> Option<(DmaPage, CommandRing)> {
    let ring = DmaPage::allocate(bdf, dma_mask)?;
    let link = Trb::link(ring.dma(), true)?;
    for (word, value) in link.dword.iter().enumerate() {
        if !ring.write32(((TRBS_PER_SEGMENT - 1) * TRB_BYTES + word * 4) as u64, *value) { return None; }
    }
    ring.clean_to_device();
    let producer = CommandRing::new(ring.dma())?;
    Some((ring, producer))
}

fn submit_transfer(mmio: &Mmio, slot: u8, endpoint: u8, producer: &mut CommandRing, ring: &DmaPage, buffer: u64, length: u32) -> Option<u64> {
    let endpoint_id = (endpoint & 0x0f).checked_mul(2)?.checked_add(u8::from(endpoint & 0x80 != 0))?;
    let trb = Trb::normal(buffer, length)?;
    let (pa, _) = producer.push(trb);
    let index = pa.checked_sub(ring.dma())?.checked_div(TRB_BYTES as u64)? as usize;
    let written = producer.trb(index)?;
    for (word, value) in written.dword.iter().enumerate() { if !ring.write32((index * TRB_BYTES + word * 4) as u64, *value) { return None; } }
    ring.clean_to_device();
    mmio.ring_endpoint_doorbell(slot, endpoint_id).then_some(pa)
}

fn pages_for(length: usize) -> Option<usize> {
    length.checked_add(DmaPage::BYTES - 1)?.checked_div(DmaPage::BYTES)
}

fn ensure_storage_pages(bdf: pci::Bdf, dma_mask: u64, pages: &mut Vec<DmaPage>, length: usize) -> Option<()> {
    let needed = pages_for(length)?;
    if needed > crate::ring::COMMAND_USABLE_TRBS { return None; }
    while pages.len() < needed { pages.push(DmaPage::allocate(bdf, dma_mask)?); }
    Some(())
}

fn submit_transfer_pages(mmio: &Mmio, slot: u8, endpoint: u8, producer: &mut CommandRing, ring: &DmaPage, pages: &[DmaPage], length: usize) -> Option<u64> {
    let endpoint_id = (endpoint & 0x0f).checked_mul(2)?.checked_add(u8::from(endpoint & 0x80 != 0))?;
    let count = pages_for(length)?;
    if count == 0 || count > pages.len() || count > producer.capacity() { return None; }
    let mut remaining = length;
    let mut completion = None;
    for (index, page) in pages.iter().take(count).enumerate() {
        let bytes = remaining.min(DmaPage::BYTES) as u32;
        let last = index + 1 == count;
        let trb = Trb::normal_chain(page.dma(), bytes, !last, last)?;
        let (pa, _) = producer.push(trb);
        let ring_index = pa.checked_sub(ring.dma())?.checked_div(TRB_BYTES as u64)? as usize;
        let written = producer.trb(ring_index)?;
        for (word, value) in written.dword.iter().enumerate() { if !ring.write32((ring_index * TRB_BYTES + word * 4) as u64, *value) { return None; } }
        remaining = remaining.checked_sub(bytes as usize)?;
        completion = Some(pa);
    }
    if remaining != 0 { return None; }
    ring.clean_to_device();
    mmio.ring_endpoint_doorbell(slot, endpoint_id).then_some(completion?)
}
