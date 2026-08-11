//! PCI admission and reset ownership for native xHCI controllers.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::platform::Mmio;
use crate::regs::XHCI_CLASS24;
use crate::{controller, platform::DmaPage, ring::{Trb, TRBS_PER_SEGMENT}};
use crate::irq::Binding;
use crate::command::CommandTransport;
use crate::device::AddressDeviceDma;

struct Record {
    bdf: pci::Bdf,
    command_orig: u16,
    mmio: Mmio,
    irq: Binding,
    _command: CommandTransport,
    _dcbaa: DmaPage,
    _device: Option<AddressDeviceDma>,
    slot: u8,
    reports: Vec<Vec<u8>>,
    _erst: DmaPage,
    _event: DmaPage,
}
static CONTROLLERS: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());
#[cfg(target_os = "oxide-kernel")]
type XhciBh = sched::bh::SchedBh;

fn input_bottom_half() {
    let mut controllers = CONTROLLERS.lock_bh::<XhciBh>();
    for record in controllers.iter_mut() {
        let Some(device) = record._device.as_mut() else { continue; };
        let Some(pending) = device.hid_pending() else { continue; };
        let Some(completion) = record.irq.take_transfer_completion(pending) else { continue; };
        if let Some(report) = device.take_hid_report(completion) {
            if record.reports.len() == 64 { record.reports.remove(0); }
            record.reports.push(report);
            let _ = device.submit_hid_report(&record.mmio, record.slot);
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
    let record = {
        let mut controllers = CONTROLLERS.lock();
        controllers.iter().position(|record| record.bdf == bdf).map(|index| controllers.remove(index))
    };
    if let Some(record) = record {
        let _ = record.mmio.halt();
        record.irq.disable_and_free();
        restore_bus_master(record.bdf, record.command_orig);
    }
}

fn prepare_dma(mmio: &Mmio) -> Option<(DmaPage, DmaPage, DmaPage, DmaPage)> {
    let command = DmaPage::allocate()?;
    let dcbaa = DmaPage::allocate()?;
    let erst = DmaPage::allocate()?;
    let event = DmaPage::allocate()?;
    let link = Trb::link(command.pa(), true)?;
    for (index, word) in link.dword.iter().enumerate() {
        if !command.write32(((TRBS_PER_SEGMENT - 1) * 16 + index * 4) as u64, *word) { return None; }
    }
    // ERST entry zero: event-ring segment base then its 256 TRBs.
    if !erst.write32(0, event.pa() as u32)
        || !erst.write32(4, (event.pa() >> 32) as u32)
        || !erst.write32(8, TRBS_PER_SEGMENT as u32)
    { return None; }
    command.clean_to_device();
    dcbaa.clean_to_device();
    erst.clean_to_device();
    event.clean_to_device();
    let plan = controller::run_plan(mmio.geometry(), command.pa(), dcbaa.pa(), erst.pa(), event.pa())?;
    if !mmio.program_halted(plan) { return None; }
    Some((command, dcbaa, erst, event))
}

fn control_complete(irq: Binding, status_pa: u64, slot: u8) -> bool {
    irq.wait_transfer_completion(status_pa, 1_000_000_000).is_some_and(|completion| {
        completion.completion_code == crate::ring::COMPLETION_SUCCESS
            && completion.residual == 0 && completion.endpoint_id == 1 && completion.slot == slot
    })
}

/// Linux's two-stage GET_DESCRIPTOR(Configuration) sequence for configuration zero.
fn fetch_first_configuration(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let Some(header_td) = crate::usb::get_configuration_descriptor_trbs(device.descriptor_pa(), 0, crate::usb::CONFIG_DESC_HEADER_BYTES) else { return false; };
    let Some(header_status) = device.submit_ep0(mmio, slot, &header_td) else { return false; };
    if !control_complete(irq, header_status, slot) { return false; }
    let Some(header) = device.configuration_header() else { return false; };
    let Some(full_td) = crate::usb::get_configuration_descriptor_trbs(device.descriptor_pa(), 0, header.total_length) else { return false; };
    let Some(full_status) = device.submit_ep0(mmio, slot, &full_td) else { return false; };
    if !control_complete(irq, full_status, slot) || device.configuration_header() != Some(header) { return false; }
    let _ = device.discover_hid_boot();
    true
}

fn configure_hid_endpoint(mmio: &Mmio, command: &mut CommandTransport, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    match device.prepare_hid_endpoint() {
        Some(false) => true,
        Some(true) => {
            let Some(configure) = Trb::configure_endpoint(device.input_pa(), slot) else { return false; };
            let Some(configure_pa) = command.submit(mmio, configure) else { return false; };
            irq.wait_command_completion(configure_pa, 1_000_000_000).is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot)
        }
        None => false,
    }
}

fn set_hid_configuration(mmio: &Mmio, irq: Binding, device: &mut AddressDeviceDma, slot: u8) -> bool {
    let Some(value) = device.hid_configuration() else { return true; };
    let Some(td) = crate::usb::set_configuration_trbs(value) else { return false; };
    let Some(status_pa) = device.submit_ep0(mmio, slot, &td) else { return false; };
    control_complete(irq, status_pa, slot)
}

fn arm_hid_interrupt_in(mmio: &Mmio, device: &mut AddressDeviceDma, slot: u8) -> bool {
    device.hid_configuration().is_none() || device.submit_hid_report(mmio, slot).is_some()
}

fn address_first_usb2(mmio: &Mmio, command: &mut CommandTransport, dcbaa: &DmaPage, irq: Binding) -> Option<AddressDeviceDma> {
    for port in 1..=mmio.geometry().max_ports {
        let Some(status) = mmio.port_status(port) else { continue; };
        // USB3 requires protocol-capability mapping and warm-reset handling.
        if status & crate::ports::PORT_CONNECT == 0 || ((status & crate::ports::PORT_SPEED_MASK) >> 10) >= 4 { continue; }
        if !mmio.reset_usb2_port(port) { continue; }
        let Some(portsc) = mmio.port_status(port) else { continue; };
        let enable_pa = command.submit(mmio, Trb::enable_slot())?;
        let enable = irq.wait_command_completion(enable_pa, 1_000_000_000)?;
        if enable.completion_code != crate::ring::COMPLETION_SUCCESS || enable.slot == 0 { continue; }
        let Some(mut device) = AddressDeviceDma::allocate(mmio.geometry().context_bytes, port, portsc) else { return None; };
        if !device.publish_dcbaa(dcbaa, enable.slot) { return None; }
        let Some(address) = Trb::address_device(device.input_pa(), enable.slot, false) else { return None; };
        let Some(address_pa) = command.submit(mmio, address) else { return None; };
        let addressed = irq.wait_command_completion(address_pa, 1_000_000_000);
        if addressed.is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == enable.slot) {
            let Some(td) = crate::usb::get_device_descriptor_trbs(device.descriptor_pa()) else { return None; };
            let Some(status_pa) = device.submit_ep0(mmio, enable.slot, &td) else { return None; };
            if control_complete(irq, status_pa, enable.slot) {
                if let Some(descriptor) = device.device_descriptor() {
                    match device.prepare_evaluate_ep0(descriptor.max_packet0) {
                        Some(false) => if fetch_first_configuration(mmio, irq, &mut device, enable.slot) && configure_hid_endpoint(mmio, command, irq, &mut device, enable.slot) && set_hid_configuration(mmio, irq, &mut device, enable.slot) && arm_hid_interrupt_in(mmio, &mut device, enable.slot) { return Some(device); },
                        Some(true) => {
                            if let Some(evaluate) = Trb::evaluate_context(device.input_pa(), enable.slot) {
                                if let Some(evaluate_pa) = command.submit(mmio, evaluate) {
                                    if irq.wait_command_completion(evaluate_pa, 1_000_000_000).is_some_and(|completion| completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == enable.slot) && fetch_first_configuration(mmio, irq, &mut device, enable.slot) && configure_hid_endpoint(mmio, command, irq, &mut device, enable.slot) && set_hid_configuration(mmio, irq, &mut device, enable.slot) && arm_hid_interrupt_in(mmio, &mut device, enable.slot) { return Some(device); }
                                }
                            }
                        }
                        None => {}
                    }
                }
            }
        }
        if let Some(disable) = Trb::disable_slot(enable.slot) {
            if let Some(disable_pa) = command.submit(mmio, disable) { let _ = irq.wait_command_completion(disable_pa, 1_000_000_000); }
        }
    }
    None
}

/// Native xHCI PCI controller driver. Controller publication follows reset;
/// command/event-ring activation is added only with its complete DMA/IRQ path.
pub struct XhciDriver;

impl drv::Driver for XhciDriver {
    fn name(&self) -> &'static str { "xhci" }
    fn matches(&self, dev: &drv::Device) -> bool { dev.bus == "pci" && dev.class == XHCI_CLASS24 }
    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let _ = softirq::set_handler(softirq::Slot::UsbInput, input_bottom_half);
        let bdf = pci::parse_bdf_addr(&dev.addr).ok_or(drv::Error::ProbeFailed)?;
        let resource = dev.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0).ok_or(drv::Error::ProbeFailed)?;
        let bytes = resource.end.checked_sub(resource.start).and_then(|length| length.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        let command_orig = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: BAR0 was enumerated for this matched PCI function and this
        // probe owns it until the symmetric remove path releases its Mapping.
        let Some(mmio) = (unsafe { Mmio::map(resource.start, bytes) }) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        if !mmio.halt_reset() { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); }
        let Some((command, dcbaa, erst, event)) = prepare_dma(&mmio) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        let Some(mut command) = CommandTransport::new(command) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        let Some(irq) = crate::irq::bind(bdf) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        if !irq.arm(&mmio, &event) || !mmio.run() {
            irq.disable_and_free();
            restore_bus_master(bdf, command_orig);
            return Err(drv::Error::ProbeFailed);
        }
        let device = address_first_usb2(&mmio, &mut command, &dcbaa, irq);
        let slot = device.as_ref().map_or(0, AddressDeviceDma::slot);
        CONTROLLERS.lock().push(Record { bdf, command_orig, mmio, irq, _command: command, _dcbaa: dcbaa, _device: device, slot, reports: Vec::new(), _erst: erst, _event: event });
        Ok(())
    }
    fn remove(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove(bdf); } }
    fn shutdown(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove(bdf); } }
}

pub static XHCI_DRIVER: XhciDriver = XhciDriver;
