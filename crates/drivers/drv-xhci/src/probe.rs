//! PCI admission and reset ownership for native xHCI controllers.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::platform::Mmio;
use crate::regs::XHCI_CLASS24;
use crate::{controller, platform::DmaPage, ring::{Trb, TRBS_PER_SEGMENT}};

struct Record {
    bdf: pci::Bdf,
    command_orig: u16,
    mmio: Mmio,
    _command: DmaPage,
    _dcbaa: DmaPage,
    _erst: DmaPage,
    _event: DmaPage,
}
static CONTROLLERS: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());

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
        let _ = record.mmio.write32(record.mmio.geometry().operational + crate::controller::USBCMD, 0);
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

/// Native xHCI PCI controller driver. Controller publication follows reset;
/// command/event-ring activation is added only with its complete DMA/IRQ path.
pub struct XhciDriver;

impl drv::Driver for XhciDriver {
    fn name(&self) -> &'static str { "xhci" }
    fn matches(&self, dev: &drv::Device) -> bool { dev.bus == "pci" && dev.class == XHCI_CLASS24 }
    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let bdf = pci::parse_bdf_addr(&dev.addr).ok_or(drv::Error::ProbeFailed)?;
        let resource = dev.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0).ok_or(drv::Error::ProbeFailed)?;
        let bytes = resource.end.checked_sub(resource.start).and_then(|length| length.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        let command_orig = enable_bus_master(bdf).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: BAR0 was enumerated for this matched PCI function and this
        // probe owns it until the symmetric remove path releases its Mapping.
        let Some(mmio) = (unsafe { Mmio::map(resource.start, bytes) }) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        if !mmio.halt_reset() { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); }
        let Some((command, dcbaa, erst, event)) = prepare_dma(&mmio) else { restore_bus_master(bdf, command_orig); return Err(drv::Error::ProbeFailed); };
        CONTROLLERS.lock().push(Record { bdf, command_orig, mmio, _command: command, _dcbaa: dcbaa, _erst: erst, _event: event });
        Ok(())
    }
    fn remove(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove(bdf); } }
    fn shutdown(&self, dev: &drv::Device) { if let Some(bdf) = pci::parse_bdf_addr(&dev.addr) { remove(bdf); } }
}

pub static XHCI_DRIVER: XhciDriver = XhciDriver;
