//! Root-port AER service binding and root-status acknowledgement.

use alloc::sync::Arc;

const ROOT_COMMAND_OFF: u16 = 0x2c;
const ROOT_STATUS_OFF: u16 = 0x30;
const ROOT_ERROR_SOURCE_OFF: u16 = 0x34;
const UNCOR_STATUS_OFF: u16 = 0x04;
const COR_STATUS_OFF: u16 = 0x10;
const ROOT_STATUS_ERROR_MASK: u32 = 0x3f;
const ROOT_COMMAND_MESSAGE_MASK: u32 = 0x7;
const PCIE_DEV_STATUS_OFF: u16 = 0x0a;
const PCIE_ROOT_CONTROL_OFF: u16 = 0x1c;
const PCIE_ROOT_SYSTEM_ERROR_MASK: u16 = 0x7;

pub(super) static AER_DRIVER: AerDriver = AerDriver;
pub(super) struct AerDriver;

impl drv::Driver for AerDriver {
    fn bus(&self) -> &'static str { "pcie-port" }
    fn name(&self) -> &'static str { "aer" }
    fn matches(&self, dev: &drv::Device) -> bool {
        pcie_port::service_port(dev, pcie_port::Service::Aer).is_some()
    }
    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let port = pcie_port::service_port(dev, pcie_port::Service::Aer).ok_or(drv::Error::NoMatch)?;
        // The current PCI IRQ owner programs one MSI message. A nonzero AER
        // message needs a multi-message allocation, so leave it fully inert.
        if port.child(pcie_port::Service::Aer).is_none_or(|child| child.message_number != 0) {
            return Err(drv::Error::ProbeFailed);
        }
        let binding = pci_irq::request_msi_only(port.root_bdf(), arch_irq::DeviceAction::PcieAer, aer_irq)
            .ok_or(drv::Error::ProbeFailed)?;
        enable(port.root_bdf());
        port.retain_binding(binding);
        Ok(())
    }
    fn remove(&self, dev: &drv::Device) {
        if let Some(port) = pcie_port::service_port(dev, pcie_port::Service::Aer) {
            disable(port.root_bdf());
        }
    }
}

fn aer_irq() {
    for dev in drv::devices() {
        let Some(port) = pcie_port::service_port(&dev, pcie_port::Service::Aer) else { continue; };
        if !port.begin_aer() { continue; }
        let Some((status, source)) = acknowledge(port.root_bdf()) else { let _ = port.cancel_aer(); continue; };
        mask_reporting(port.root_bdf());
        port.publish_aer(status, source);
        if !sched::live::workqueue::queue_work(recover_work, bdf_key(port.root_bdf())) {
            if port.cancel_aer() { unmask_reporting(port.root_bdf()); }
            klog::write_raw(b"pcie_aer_workqueue_full\n");
        }
    }
}

fn enable(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { enable_with(&r, bdf); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { enable_with(&r, bdf); }
}

fn enable_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) {
        let Some(aer) = pci::extended_capability(r, bdf, pci::EXT_CAP_ID_AER) else { return; };
        let Some(pcie) = pci::capabilities(r, bdf).find(pci::CAP_ID_PCIE).map(|cap| cap.cfg_off as u16) else { return; };
        let devsta = r.read16_ext(bdf, pcie + PCIE_DEV_STATUS_OFF);
        r.write16_ext(bdf, pcie + PCIE_DEV_STATUS_OFF, devsta);
        let rootctl = r.read16_ext(bdf, pcie + PCIE_ROOT_CONTROL_OFF);
        r.write16_ext(bdf, pcie + PCIE_ROOT_CONTROL_OFF, rootctl & !PCIE_ROOT_SYSTEM_ERROR_MASK);
        clear_status(r, bdf, aer);
        let command = r.read32_ext(bdf, aer + ROOT_COMMAND_OFF);
        r.write32_ext(bdf, aer + ROOT_COMMAND_OFF, command | ROOT_COMMAND_MESSAGE_MASK);
}

fn disable(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { disable_with(&r, bdf); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { disable_with(&r, bdf); }
}

fn disable_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) {
        let Some(aer) = pci::extended_capability(r, bdf, pci::EXT_CAP_ID_AER) else { return; };
        let command = r.read32_ext(bdf, aer + ROOT_COMMAND_OFF);
        r.write32_ext(bdf, aer + ROOT_COMMAND_OFF, command & !ROOT_COMMAND_MESSAGE_MASK);
        let root = r.read32_ext(bdf, aer + ROOT_STATUS_OFF);
        r.write32_ext(bdf, aer + ROOT_STATUS_OFF, root);
}

fn acknowledge(bdf: pci::Bdf) -> Option<(u32, u32)> {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { return acknowledge_with(&r, bdf); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { return acknowledge_with(&r, bdf); }
    None
}

fn acknowledge_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) -> Option<(u32, u32)> {
        let Some(aer) = pci::extended_capability(r, bdf, pci::EXT_CAP_ID_AER) else { return None; };
        let root = r.read32_ext(bdf, aer + ROOT_STATUS_OFF);
        if root & ROOT_STATUS_ERROR_MASK == 0 { return None; }
        let source = r.read32_ext(bdf, aer + ROOT_ERROR_SOURCE_OFF);
        r.write32_ext(bdf, aer + ROOT_STATUS_OFF, root);
        Some((root, source))
}

fn mask_reporting(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { report_mask_with(&r, bdf, false); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { report_mask_with(&r, bdf, false); }
}

fn unmask_reporting(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { report_mask_with(&r, bdf, true); }
    #[cfg(target_arch = "aarch64")]
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { report_mask_with(&r, bdf, true); }
}

fn report_mask_with<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, enable: bool) {
    let Some(aer) = pci::extended_capability(r, bdf, pci::EXT_CAP_ID_AER) else { return; };
    let command = r.read32_ext(bdf, aer + ROOT_COMMAND_OFF);
    let command = if enable { command | ROOT_COMMAND_MESSAGE_MASK } else { command & !ROOT_COMMAND_MESSAGE_MASK };
    r.write32_ext(bdf, aer + ROOT_COMMAND_OFF, command);
}

fn recover_work(key: usize) {
    let bdf = bdf_from_key(key);
    let Some(port) = pcie_port::find(bdf) else { return; };
    let Some((status, source)) = port.take_aer() else { return; };
    let _ = pcie_port::recover_aer(bdf, status, source);
    if port.finish_aer() { unmask_reporting(bdf); }
}

fn bdf_key(bdf: pci::Bdf) -> usize { ((u32::from(bdf.segment) << 16) | u32::from(bdf.raw())) as usize }

fn bdf_from_key(key: usize) -> pci::Bdf {
    let raw = key as u32;
    let requester = raw as u16;
    pci::Bdf { segment: (raw >> 16) as u16, bus: (requester >> 8) as u8,
        device: ((requester >> 3) & 0x1f) as u8, function: (requester & 7) as u8 }
}

fn clear_status<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf, aer: u16) {
    let root = r.read32_ext(bdf, aer + ROOT_STATUS_OFF);
    r.write32_ext(bdf, aer + ROOT_STATUS_OFF, root);
    let cor = r.read32_ext(bdf, aer + COR_STATUS_OFF);
    r.write32_ext(bdf, aer + COR_STATUS_OFF, cor);
    let uncor = r.read32_ext(bdf, aer + UNCOR_STATUS_OFF);
    r.write32_ext(bdf, aer + UNCOR_STATUS_OFF, uncor);
}
