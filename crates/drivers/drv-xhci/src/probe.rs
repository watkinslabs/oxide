//! PCI admission and reset ownership for native xHCI controllers.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::platform::Mmio;
use crate::regs::XHCI_CLASS24;
use crate::{controller, platform::DmaPage, ring::{Trb, TRBS_PER_SEGMENT}};
use crate::irq::Binding;
use crate::command::CommandTransport;
use crate::device::AddressDeviceDma;
#[cfg(feature = "debug-boot")]
fn probe_stage(stage: &'static [u8]) { klog::write_raw(stage); }

#[cfg(feature = "debug-boot")]
fn port_stage(port: u8, stage: &'static [u8]) {
    klog::write_raw(b"[WARN]  xhci: port=");
    klog::write_dec_u64(port as u64);
    klog::write_raw(b" ");
    klog::write_raw(stage);
    klog::write_raw(b"\n");
}

pub(crate) struct UsbDeviceState {
    pub(crate) device: AddressDeviceDma,
    pub(crate) slot: u8,
    pub(crate) decoder: Option<crate::hid_report::ReportDecoder>,
    pub(crate) evdev: Option<u32>,
    pub(crate) input_platform: Option<u32>,
    pub(crate) storage_name: Option<block::ScsiDiskName>,
}

pub(crate) struct UsbDevice { _controller: Weak<Controller>, pub(crate) state: Spinlock<UsbDeviceState, DriverLockClass> }

impl UsbDevice {
    /// Construct the input-facing device before taking the controller lock. # C: O(input registration)
    pub(crate) fn new(controller: &Arc<Controller>, device: AddressDeviceDma) -> Arc<Self> {
        let slot = device.slot();
        let layout = device.hid_layout();
        let evdev = crate::probe_input::install_hid_input(controller.bdf, slot, layout);
        let input_platform = evdev.map(|_| crate::probe_input::platform_id(controller.bdf, slot));
        Arc::new(Self { _controller: Arc::downgrade(controller), state: Spinlock::new(UsbDeviceState { device, slot, decoder: layout.map(crate::hid_report::ReportDecoder::new), evdev, input_platform, storage_name: None }) })
    }

    pub(crate) fn with_transport<T>(&self, f: impl FnOnce(&Mmio, Binding, &CommandTransport, &mut UsbDeviceState) -> T) -> Option<T> {
        let controller = self._controller.upgrade()?;
        let mut controller = controller.state.lock_bh::<XhciBh>();
        let mut device = self.state.lock_bh::<XhciBh>();
        let ControllerState { mmio, irq, command, .. } = &mut *controller;
        Some(f(mmio, *irq, command, &mut device))
    }
}

pub(crate) struct ControllerState {
    pub(crate) mmio: Arc<Mmio>,
    pub(crate) irq: Binding,
    pub(crate) command: Arc<CommandTransport>,
    pub(crate) _dcbaa: Arc<DmaPage>,
    pub(crate) devices: Vec<Arc<UsbDevice>>,
    _erst: DmaPage,
    _event: DmaPage,
}
pub(crate) struct Controller { pub(crate) bdf: pci::Bdf, command_orig: u16, pub(crate) state: Spinlock<ControllerState, DriverLockClass> }
pub(crate) static CONTROLLERS: Spinlock<Vec<Arc<Controller>>, DriverLockClass> = Spinlock::new(Vec::new());
#[cfg(target_os = "oxide-kernel")]
pub(crate) type XhciBh = sched::bh::SchedBh;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type XhciBh = sync::NoopBh;

/// Publish an already-bound USB device under the short controller lock. # C: O(1)
pub(crate) fn add_usb_device(state: &mut ControllerState, device: Arc<UsbDevice>) -> Arc<UsbDevice> {
    state.devices.push(Arc::clone(&device));
    if device.state.lock_bh::<XhciBh>().device.hub_events_pending() { crate::probe_hub::queue_hub_work(); }
    device
}

fn input_bottom_half() {
    let controllers = CONTROLLERS.lock_bh::<XhciBh>();
    for controller in controllers.iter() {
        let devices = controller.state.lock_bh::<XhciBh>().devices.clone();
        for device in devices {
            let _ = device.with_transport(|mmio, irq, _, state| {
                if let Some(pending) = state.device.hid_pending() {
                    if let Some(completion) = irq.take_transfer_completion(pending) {
                        if let Some(report) = state.device.take_hid_report(completion) {
                            crate::probe_input::publish_report(state, &report);
                            let slot = state.slot;
                            let _ = state.device.submit_hid_report(mmio, slot);
                        }
                    }
                }
                if let Some(pending) = state.device.hub_pending() {
                    if let Some(completion) = irq.take_transfer_completion(pending) {
                        if state.device.take_hub_status(completion).is_some() {
                            let slot = state.slot;
                            let _ = state.device.submit_hub_status(mmio, slot);
                            crate::probe_hub::queue_hub_work();
                        }
                    }
                }
            });
        }
    }
}

fn enable_bus_master(bdf: pci::Bdf) -> Option<u16> {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::pci::EcamPci::from_published().map(|reader| pci::enable_mem_bus_master(&reader, bdf)) }
}

fn restore_bus_master(bdf: pci::Bdf, command_orig: u16) {
    #[cfg(target_arch = "x86_64")]
    if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command_orig); }
    #[cfg(target_arch = "aarch64")]
    if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() { let _ = pci::restore_mem_bus_master(&reader, bdf, command_orig); }
}

fn remove(bdf: pci::Bdf) {
    let controller = {
        let mut controllers = CONTROLLERS.lock_bh::<XhciBh>();
        controllers.iter().position(|controller| controller.bdf == bdf).map(|index| controllers.remove(index))
    };
    if let Some(controller) = controller {
        let state = controller.state.lock_bh::<XhciBh>();
        let _ = state.mmio.halt();
        state.irq.disable_and_free();
        for device in &state.devices {
            let storage_name = device.state.lock_bh::<XhciBh>().storage_name.take();
            if let Some(name) = storage_name {
                if !block::unregister(name.as_str()) { device.state.lock_bh::<XhciBh>().storage_name = Some(name); }
            }
            crate::probe_input::remove_hid_input(&device.state.lock_bh::<XhciBh>());
        }
        restore_bus_master(controller.bdf, controller.command_orig);
    }
    if CONTROLLERS.lock_bh::<XhciBh>().is_empty() { let _ = softirq::clear_handler(softirq::Slot::UsbInput); }
}

fn prepare_dma(bdf: pci::Bdf, mmio: &Mmio) -> Option<(DmaPage, DmaPage, DmaPage, DmaPage)> {
    let dma_mask = mmio.geometry().dma_mask;
    let command = DmaPage::allocate(bdf, dma_mask)?;
    let dcbaa = DmaPage::allocate(bdf, dma_mask)?;
    let erst = DmaPage::allocate(bdf, dma_mask)?;
    let event = DmaPage::allocate(bdf, dma_mask)?;
    let link = Trb::link(command.dma(), true)?;
    for (index, word) in link.dword.iter().enumerate() {
        if !command.write32(((TRBS_PER_SEGMENT - 1) * 16 + index * 4) as u64, *word) { return None; }
    }
    // ERST entry zero: event-ring segment base then its 256 TRBs.
    if !erst.write32(0, event.dma() as u32)
        || !erst.write32(4, (event.dma() >> 32) as u32)
        || !erst.write32(8, TRBS_PER_SEGMENT as u32)
    { return None; }
    command.clean_to_device();
    dcbaa.clean_to_device();
    erst.clean_to_device();
    event.clean_to_device();
    let plan = controller::run_plan(mmio.geometry(), command.dma(), dcbaa.dma(), erst.dma(), event.dma())?;
    if !mmio.program_halted(plan) { return None; }
    Some((command, dcbaa, erst, event))
}

pub(crate) fn control_complete(irq: Binding, status_pa: u64, slot: u8) -> bool {
    irq.wait_transfer_completion(status_pa, 1_000_000_000).is_some_and(|completion| {
        completion.completion_code == crate::ring::COMPLETION_SUCCESS
            && completion.residual == 0 && completion.endpoint_id == 1 && completion.slot == slot
    })
}

/// Linux's two-stage GET_DESCRIPTOR(Configuration) sequence for configuration zero.
fn fetch_first_configuration(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: config header submit\n");
    let Some(header_td) = crate::usb::get_configuration_descriptor_trbs(device.descriptor_pa(), 0, crate::usb::CONFIG_DESC_HEADER_BYTES) else { return false; };
    let Some(header_status) = device.submit_ep0(mmio, slot, &header_td) else { return false; };
    if !control_complete(irq, header_status, slot) { return false; }
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: config header complete\n");
    let Some(header) = device.configuration_header() else { return false; };
    let Some(full_td) = crate::usb::get_configuration_descriptor_trbs(device.descriptor_pa(), 0, header.total_length) else { return false; };
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: config full submit\n");
    let Some(full_status) = device.submit_ep0(mmio, slot, &full_td) else { return false; };
    if !control_complete(irq, full_status, slot) || device.configuration_header() != Some(header) { return false; }
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: config full complete\n");
    let _ = device.discover_hid();
    let _ = device.discover_hub();
    let _ = device.discover_mass_storage();
    true
}

fn configure_device_endpoint(mmio: &Mmio, command: &CommandTransport, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let prepared = if device.hid_interface().is_some() { device.prepare_hid_endpoint() } else if device.hub_interface().is_some() { device.prepare_hub_endpoint() } else { device.prepare_storage_endpoints() };
    match prepared {
        Some(false) => true,
        Some(true) => {
            #[cfg(feature = "debug-boot")]
            probe_stage(b"[INFO]  xhci: endpoint configure submit\n");
            let Some(configure) = Trb::configure_endpoint(device.input_pa(), slot) else { return false; };
            let Some(configure_pa) = command.submit(mmio, configure) else { return false; };
            let done = irq.wait_command_completion(configure_pa, 1_000_000_000).is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot);
            #[cfg(feature = "debug-boot")]
            if done { probe_stage(b"[INFO]  xhci: endpoint configure complete\n"); }
            done
        }
        None => false,
    }
}

fn set_device_configuration(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let Some(value) = device.hid_configuration().or(device.hub_configuration()).or(device.storage_configuration()) else { return true; };
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: set configuration submit\n");
    let Some(td) = crate::usb::set_configuration_trbs(value) else { return false; };
    let Some(status_pa) = device.submit_ep0(mmio, slot, &td) else { return false; };
    let done = control_complete(irq, status_pa, slot);
    #[cfg(feature = "debug-boot")]
    if done { probe_stage(b"[INFO]  xhci: set configuration complete\n"); }
    done
}

fn set_hid_idle(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let Some(hid) = device.hid_interface() else { return true; };
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: hid idle submit\n");
    let td = crate::usb::set_hid_idle_trbs(hid.interface);
    let Some(status_pa) = device.submit_ep0(mmio, slot, &td) else { return false; };
    let done = control_complete(irq, status_pa, slot);
    #[cfg(feature = "debug-boot")]
    if done { probe_stage(b"[INFO]  xhci: hid idle complete\n"); }
    done
}

fn fetch_hid_report_descriptor(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let Some(hid) = device.hid_interface() else { return true; };
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: hid descriptor submit\n");
    let Some(td) = crate::usb::get_hid_report_descriptor_trbs(device.descriptor_pa(), hid.interface, hid.report_bytes) else { return false; };
    let Some(status_pa) = device.submit_ep0(mmio, slot, &td) else { return false; };
    if !control_complete(irq, status_pa, slot) { return false; }
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: hid descriptor complete\n");
    let parsed = device.discover_hid_report().is_some();
    #[cfg(feature = "debug-boot")]
    probe_stage(if parsed { b"[INFO]  xhci: hid descriptor parsed\n" } else { b"[WARN]  xhci: hid descriptor rejected\n" });
    parsed
}

fn fetch_hub_descriptor(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    if device.hub_interface().is_none() { return true; }
    let Some(header_td) = crate::usb::get_hub_descriptor_trbs(device.descriptor_pa(), crate::usb::HUB_DESC_HEADER_BYTES) else { return false; };
    let Some(header_status) = device.submit_ep0(mmio, slot, &header_td) else { return false; };
    if !control_complete(irq, header_status, slot) { return false; }
    let Some(length) = device.hub_descriptor_length() else { return false; };
    let Some(full_td) = crate::usb::get_hub_descriptor_trbs(device.descriptor_pa(), length) else { return false; };
    let Some(full_status) = device.submit_ep0(mmio, slot, &full_td) else { return false; };
    control_complete(irq, full_status, slot) && device.discover_hub_descriptor().is_some()
}

fn configure_hub_device(mmio: &Mmio, command: &CommandTransport, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    if !fetch_hub_descriptor(mmio, irq, device, slot) { return false; }
    if device.hub_interface().is_none() { return true; }
    let Some(true) = device.prepare_hub_slot(mmio.geometry().hci_version) else { return false; };
    let command_trb = if mmio.geometry().hci_version > 0x0095 { Trb::configure_endpoint(device.input_pa(), slot) } else { Trb::evaluate_context(device.input_pa(), slot) };
    let Some(command_trb) = command_trb else { return false; };
    let Some(command_pa) = command.submit(mmio, command_trb) else { return false; };
    irq.wait_command_completion(command_pa, 1_000_000_000).is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot)
}

fn arm_hid_interrupt_in(mmio: &Mmio, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let armed = device.hid_configuration().is_none() || device.submit_hid_report(mmio, slot).is_some();
    #[cfg(feature = "debug-boot")]
    if armed { probe_stage(b"[INFO]  xhci: hid interrupt armed\n"); }
    armed
}

fn arm_hub_interrupt_in(mmio: &Mmio, device: &mut AddressDeviceDma, slot: u8) -> bool {
    device.hub_configuration().is_none() || device.submit_hub_status(mmio, slot).is_some()
}

fn storage_complete(irq: Binding, trb_pa: u64, slot: u8, endpoint: u8, length: u32) -> bool {
    let endpoint_id = (endpoint & 0x0f).checked_mul(2).and_then(|id| id.checked_add(u8::from(endpoint & 0x80 != 0)));
    irq.wait_transfer_completion(trb_pa, 1_000_000_000).is_some_and(|completion| {
        completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot
            && Some(completion.endpoint_id) == endpoint_id && completion.residual <= length
    })
}

pub(crate) fn storage_command(device: &UsbDevice, tag: u32, cdb: &[u8], data_bytes: u32, device_to_host: bool, out: Option<&[u8]>) -> Option<Vec<u8>> {
    device.with_transport(|mmio, irq, _, state| {
        let storage = state.device.storage_interface()?;
        if device_to_host != out.is_none() || out.is_some_and(|bytes| bytes.len() != data_bytes as usize) { return None; }
        if let Some(bytes) = out { if !state.device.set_storage_data(bytes) { return None; } }
        let cbw = state.device.submit_storage_cbw(mmio, state.slot, tag, data_bytes, device_to_host, cdb)?;
        if !storage_complete(irq, cbw, state.slot, storage.bulk_out, crate::storage::CBW_BYTES as u32) { return None; }
        if data_bytes != 0 {
            let data = state.device.submit_storage_data(mmio, state.slot, data_bytes, device_to_host)?;
            let endpoint = if device_to_host { storage.bulk_in } else { storage.bulk_out };
            if !storage_complete(irq, data, state.slot, endpoint, data_bytes) { return None; }
        }
        let csw = state.device.submit_storage_csw(mmio, state.slot)?;
        if !storage_complete(irq, csw, state.slot, storage.bulk_in, crate::storage::CSW_BYTES as u32) { return None; }
        let (status, residue) = state.device.storage_csw(tag, data_bytes)?;
        if status != crate::storage::CswStatus::Passed || residue != 0 { return None; }
        if device_to_host { state.device.storage_data(data_bytes as usize) } else { Some(Vec::new()) }
    })?
}

pub(crate) fn probe_storage_capacity(device: &UsbDevice) -> Option<(u64, u32)> {
    if device.state.lock_bh::<XhciBh>().device.storage_interface().is_none() { return None; }
    let inquiry = storage_command(device, 1, &crate::storage::inquiry_cdb(), 36, true, None)?;
    if inquiry.len() != 36 { return None; }
    let capacity = storage_command(device, 2, &crate::storage::read_capacity10_cdb(), 8, true, None)?;
    let (last_lba, block_bytes) = crate::storage::read_capacity10(&capacity)?;
    Some((u64::from(last_lba).checked_add(1)?, block_bytes))
}

pub(crate) fn disable_slot(mmio: &Mmio, command: &CommandTransport, irq: Binding, slot: u8) {
    if let Some(disable) = Trb::disable_slot(slot) {
        if let Some(disable_pa) = command.submit(mmio, disable) { let _ = irq.wait_command_completion(disable_pa, 1_000_000_000); }
    }
}

pub(crate) fn address_port_device(bdf: pci::Bdf, mmio: &Mmio, command: &CommandTransport, dcbaa: &DmaPage, irq: Binding, port: u8) -> Option<AddressDeviceDma> {
    let Some(portsc) = mmio.port_status(port) else { #[cfg(feature = "debug-boot")] port_stage(port, b"post-reset status"); return None; };
    if portsc & (crate::ports::PORT_CONNECT | crate::ports::PORT_ENABLED) != crate::ports::PORT_CONNECT | crate::ports::PORT_ENABLED { return None; }
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: port reset\n");
    let Some(enable_pa) = command.submit(mmio, Trb::enable_slot()) else { #[cfg(feature = "debug-boot")] port_stage(port, b"enable submit"); return None; };
    let Some(enable) = irq.wait_command_completion(enable_pa, 1_000_000_000) else { #[cfg(feature = "debug-boot")] port_stage(port, b"enable completion"); return None; };
    #[cfg(feature = "debug-boot")]
    probe_stage(b"[INFO]  xhci: slot enabled\n");
    if enable.completion_code != crate::ring::COMPLETION_SUCCESS || enable.slot == 0 {
        if enable.slot != 0 { disable_slot(mmio, command, irq, enable.slot); }
        return None;
    }
    let Some(topology) = crate::context::DeviceTopology::root(port) else { #[cfg(feature = "debug-boot")] port_stage(port, b"topology"); return None; };
    let result = address_enabled_device(bdf, mmio, command, dcbaa, irq, topology, portsc, enable.slot);
    if result.is_none() {
        #[cfg(feature = "debug-boot")]
        port_stage(port, b"device address/configure");
    }
    result
}

pub(crate) fn address_hub_child(bdf: pci::Bdf, mmio: &Mmio, command: &CommandTransport,
    dcbaa: &DmaPage, irq: Binding, topology: crate::context::DeviceTopology, portsc: u32) -> Option<AddressDeviceDma>
{
    let enable_pa = command.submit(mmio, Trb::enable_slot())?;
    let enable = irq.wait_command_completion(enable_pa, 1_000_000_000)?;
    if enable.completion_code != crate::ring::COMPLETION_SUCCESS || enable.slot == 0 {
        if enable.slot != 0 { disable_slot(mmio, command, irq, enable.slot); }
        return None;
    }
    address_enabled_device(bdf, mmio, command, dcbaa, irq, topology, portsc, enable.slot)
}

fn address_enabled_device(bdf: pci::Bdf, mmio: &Mmio, command: &CommandTransport, dcbaa: &DmaPage,
    irq: Binding, topology: crate::context::DeviceTopology, portsc: u32, slot: u8) -> Option<AddressDeviceDma>
{
    let Some(mut device) = AddressDeviceDma::allocate_topology(bdf, mmio.geometry().context_bytes, mmio.geometry().dma_mask, topology, portsc) else { disable_slot(mmio, command, irq, slot); return None; };
    if !device.publish_dcbaa(dcbaa, slot) { disable_slot(mmio, command, irq, slot); return None; }
    let Some(address) = Trb::address_device(device.input_pa(), slot, false) else { disable_slot(mmio, command, irq, slot); return None; };
    let Some(address_pa) = command.submit(mmio, address) else { disable_slot(mmio, command, irq, slot); return None; };
    let addressed = irq.wait_command_completion(address_pa, 1_000_000_000);
    if addressed.is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot) {
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: device addressed\n");
        let Some(td) = crate::usb::get_device_descriptor_trbs(device.descriptor_pa()) else { disable_slot(mmio, command, irq, slot); return None; };
        let Some(status_pa) = device.submit_ep0(mmio, slot, &td) else { disable_slot(mmio, command, irq, slot); return None; };
        if control_complete(irq, status_pa, slot) {
            #[cfg(feature = "debug-boot")]
            probe_stage(b"[INFO]  xhci: device descriptor\n");
            if let Some(descriptor) = device.device_descriptor() {
                match device.prepare_evaluate_ep0(descriptor.max_packet0) {
                    Some(false) => if fetch_first_configuration(mmio, irq, &mut device, slot) && configure_device_endpoint(mmio, command, irq, &mut device, slot) && set_device_configuration(mmio, irq, &mut device, slot) && set_hid_idle(mmio, irq, &mut device, slot) && fetch_hid_report_descriptor(mmio, irq, &mut device, slot) && configure_hub_device(mmio, command, irq, &mut device, slot) && arm_hid_interrupt_in(mmio, &mut device, slot) && arm_hub_interrupt_in(mmio, &mut device, slot) { return Some(device); },
                    Some(true) => {
                        #[cfg(feature = "debug-boot")]
                        probe_stage(b"[INFO]  xhci: ep0 evaluate submit\n");
                        if let Some(evaluate) = Trb::evaluate_context(device.input_pa(), slot) {
                            if let Some(evaluate_pa) = command.submit(mmio, evaluate) {
                                if irq.wait_command_completion(evaluate_pa, 1_000_000_000).is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot) {
                                    #[cfg(feature = "debug-boot")]
                                    probe_stage(b"[INFO]  xhci: ep0 evaluate complete\n");
                                    if fetch_first_configuration(mmio, irq, &mut device, slot) && configure_device_endpoint(mmio, command, irq, &mut device, slot) && set_device_configuration(mmio, irq, &mut device, slot) && set_hid_idle(mmio, irq, &mut device, slot) && fetch_hid_report_descriptor(mmio, irq, &mut device, slot) && configure_hub_device(mmio, command, irq, &mut device, slot) && arm_hid_interrupt_in(mmio, &mut device, slot) && arm_hub_interrupt_in(mmio, &mut device, slot) { return Some(device); }
                                }
                            }
                        }
                    }
                    None => {}
                }
            }
        }
    }
    disable_slot(mmio, command, irq, slot);
    None
}

/// Native xHCI PCI controller driver. Controller publication follows reset;
/// command/event-ring activation is added only with its complete DMA/IRQ path.
pub struct XhciDriver;

impl drv::Driver for XhciDriver {
    fn name(&self) -> &'static str { "xhci" }
    fn matches(&self, dev: &drv::Device) -> bool { dev.bus == "pci" && dev.class == XHCI_CLASS24 }
    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: probe\n");
        let _ = softirq::set_handler(softirq::Slot::UsbInput, input_bottom_half);
        let bdf = pci::parse_bdf_addr(&dev.addr).ok_or(drv::Error::ProbeFailed)?;
        let resource = dev.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0).ok_or(drv::Error::ProbeFailed)?;
        let bytes = resource.end.checked_sub(resource.start).and_then(|length| length.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  xhci: bar0 start=");
            klog::write_hex_u64(resource.start);
            klog::write_raw(b" bytes=");
            klog::write_hex_u64(bytes);
            klog::write_raw(b"\n");
        }
        let command_orig = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: BAR0 was enumerated for this matched PCI function and this
        // probe owns it until the symmetric remove path releases its Mapping.
        let Some(mmio) = (unsafe { Mmio::map(resource.start, bytes) }) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        let force_handoff = (dev.vendor_id == 0x104c && dev.device_id == 0x8241)
            || (dev.vendor_id == 0x1912 && dev.device_id == 0x0014);
        if !mmio.legacy_handoff(force_handoff) { #[cfg(feature = "debug-boot")] probe_stage(b"[WARN]  xhci: legacy handoff\n"); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); }
        if !mmio.halt_reset() { #[cfg(feature = "debug-boot")] probe_stage(b"[WARN]  xhci: halt reset\n"); restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); }
        let Some((command, dcbaa, erst, event)) = prepare_dma(bdf, &mmio) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        let Some(command) = CommandTransport::new(command) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        let Some(irq) = crate::irq::bind(bdf, &mmio) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        if !irq.arm(&mmio, &event) {
            irq.disable_and_free();
            restore_bus_master(bdf, command_orig);
            return Err(drv::Error::ProbeFailed);
        }
        let controller = Arc::new(Controller {
            bdf,
            command_orig,
            state: Spinlock::new(ControllerState { mmio: Arc::new(mmio), irq, command: Arc::new(command), _dcbaa: Arc::new(dcbaa), devices: Vec::new(), _erst: erst, _event: event }),
        });
        let (ports, irq) = {
            let state = controller.state.lock_bh::<XhciBh>();
            (state.mmio.geometry().max_ports, state.irq)
        };
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: publishing\n");
        // Publish ownership before controller Run: a port-status interrupt can
        // arrive immediately after Run, and its bottom half must always find
        // the controller that owns the event ring.
        CONTROLLERS.lock_bh::<XhciBh>().push(Arc::clone(&controller));
        if !controller.state.lock_bh::<XhciBh>().mmio.run() {
            remove(bdf);
            return Err(drv::Error::ProbeFailed);
        }
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: running\n");
        // Initial root-hub discovery enters process-context work directly.
        // The worker may not exist until the kthread phase, so the item stays
        // queued; later port-status interrupts use UsbInput to queue the same
        // worker without ever performing enumeration in interrupt context.
        {
            let state = controller.state.lock_bh::<XhciBh>();
            for port in 1..=ports { let _ = state.mmio.power_port(port); }
        }
        irq.seed_port_changes(ports);
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: ports seeded\n");
        if !crate::root_hub::queue_root_work() {
            #[cfg(feature = "debug-boot")]
            probe_stage(b"[WARN]  xhci: root queue full\n");
        }
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: root queued\n");
        #[cfg(feature = "debug-boot")]
        probe_stage(b"[INFO]  xhci: published\n");
        Ok(())
    }
    fn remove(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove(bdf); } }
    fn shutdown(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove(bdf); } }
}

pub static XHCI_DRIVER: XhciDriver = XhciDriver;
