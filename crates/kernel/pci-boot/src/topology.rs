//! PCI model publication in hardware bridge ancestry order.

use alloc::{sync::Arc, vec::Vec};

pub(super) fn publish_scanned_devices(devs: &[pci::PciDevice]) {
    for d in devs {
        debug_boot! {
            klog::write_raw(b"[INFO]  pci ");
            klog::write_dec_u64(d.bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(d.bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(d.bdf.function as u64);
            klog::write_raw(b" vendor=");
            klog::write_hex_u64(d.vendor_id as u64);
            klog::write_raw(b" device=");
            klog::write_hex_u64(d.device_id as u64);
            klog::write_raw(b" class=");
            klog::write_hex_u64(d.class_code as u64);
            klog::write_raw(b"\n");
        }
        super::trace::bar_dump_arch(d.bdf);
        super::trace::cap_dump_arch(d);
    }
    let mut pending: Vec<&pci::PciDevice> = devs.iter().collect();
    while !pending.is_empty() {
        let mut next = Vec::new();
        let mut progressed = false;
        for d in pending {
            if publish_scanned_device(d, devs).is_some() { progressed = true; } else { next.push(d); }
        }
        if !progressed { break; }
        pending = next;
    }
    debug_boot! {
        for d in devs {
            let addr = addr(d.bdf);
            let bound = drv::devices().into_iter().find(|dev| dev.bus == "pci" && dev.addr == addr)
                .and_then(|dev| dev.bound());
            klog::write_raw(b"[INFO]  pci driver=");
            klog::write_raw(bound.unwrap_or("none").as_bytes());
            klog::write_raw(b"\n");
        }
    }
}

fn publish_scanned_device(d: &pci::PciDevice, scanned: &[pci::PciDevice]) -> Option<Arc<drv::Device>> {
    let class = ((d.class_code as u32) << 16) | ((d.subclass as u32) << 8) | d.prog_if as u32;
    let parent = model_parent(d.bdf, scanned)?;
    publish_model_device(d, addr(d.bdf), class, parent)
}

fn publish_model_device(d: &pci::PciDevice, addr: alloc::string::String, class: u32,
    parent: Option<Arc<drv::Device>>) -> Option<Arc<drv::Device>> {
    let dev = Arc::new(drv::Device::new("pci", addr.clone(), d.vendor_id, d.device_id, class)
        .with_pci_ident(super::config_access::pci_ident(d))
        .with_resources(super::pci_resources_arch(d)));
    let added = match parent {
        Some(parent) => drv::try_device_add_with_parent(dev, &parent),
        None => drv::try_device_add(dev),
    };
    match added {
        Ok(dev) => { publish_port_service_children(d, &dev); Some(dev) }
        Err(drv::Error::Busy) => drv::devices().into_iter().find(|dev| dev.bus == "pci"
            && dev.addr == addr && dev.vendor_id == d.vendor_id && dev.device_id == d.device_id && dev.class == class),
        Err(_) => None,
    }
}

fn model_parent(child: pci::Bdf, scanned: &[pci::PciDevice]) -> Option<Option<Arc<drv::Device>>> {
    let bridges = bridge_windows(scanned);
    let parent = pci::parent_bridge(&bridges, child);
    if parent.is_none() && bridges.iter().any(|(bridge, window)| bridge.segment == child.segment
        && child.bus >= window.secondary && child.bus <= window.subordinate) {
        return None;
    }
    match parent {
        None => Some(None),
        Some(bdf) => drv::devices().into_iter().find(|dev| dev.bus == "pci" && dev.addr == addr(bdf)).map(Some),
    }
}

fn bridge_windows(scanned: &[pci::PciDevice]) -> Vec<(pci::Bdf, pci::BridgeBuses)> {
    #[cfg(target_arch = "x86_64")]
    { return hal_x86_64::pci::EcamPci::from_published().map(|reader| scanned.iter()
        .filter_map(|d| pci::bridge_buses(&reader, d.bdf).map(|window| (d.bdf, window))).collect()).unwrap_or_default(); }
    #[cfg(target_arch = "aarch64")]
    { return hal_aarch64::pci::EcamPci::from_published().map(|reader| scanned.iter()
        .filter_map(|d| pci::bridge_buses(&reader, d.bdf).map(|window| (d.bdf, window))).collect()).unwrap_or_default(); }
}

fn publish_port_service_children(d: &pci::PciDevice, parent: &Arc<drv::Device>) {
    if !firmware::acpi::pci_osc_control(d.bdf.segment, d.bdf.bus)
        .is_some_and(|osc| osc.control & firmware::acpi::OSC_PCIE_AER_CONTROL != 0) { return; }
    let message = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::pci::EcamPci::from_published().and_then(|reader| pci::aer_message_number(&reader, d.bdf)) }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::pci::EcamPci::from_published().and_then(|reader| pci::aer_message_number(&reader, d.bdf)) }
    };
    let port_type = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::pci::EcamPci::from_published().and_then(|reader| pci::pcie_type(&reader, d.bdf)) }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::pci::EcamPci::from_published().and_then(|reader| pci::pcie_type(&reader, d.bdf)) }
    };
    if !matches!(port_type, Some(pci::PcieType::RootPort | pci::PcieType::RootComplexEvent)) { return; }
    let Some(message) = message else { return; };
    let _ = pcie_port::publish(d.bdf, Arc::clone(parent), pcie_port::Service::Aer.bit(), [0, message, 0, 0, 0]);
}

fn addr(bdf: pci::Bdf) -> alloc::string::String {
    alloc::format!("{:04x}:{:02x}:{:02x}.{}", bdf.segment, bdf.bus, bdf.device, bdf.function)
}
