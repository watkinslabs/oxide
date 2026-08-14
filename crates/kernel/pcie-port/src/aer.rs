//! Process-context AER recovery callback coordination.

use alloc::{sync::Arc, vec::Vec};

const ROOT_UNCORRECTABLE_RECEIVED: u32 = 1 << 2;
const ROOT_FATAL_RECEIVED: u32 = 1 << 6;
const ROOT_UNCORRECTABLE_SOURCE_SHIFT: u32 = 16;
const PCI_HEADER_TYPE_MASK: u8 = 0x7f;
const PCI_HEADER_TYPE_BRIDGE: u8 = 0x01;

/// Terminal result of one root-port AER recovery attempt.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Recovery { IgnoredCorrectable, SourceMissing, ResetRequired, Disconnected, Recovered }

/// Recover an acknowledged native AER event in process context. The source
/// must be a live descendant of the port; no endpoint status is changed here.
/// # C: O(devices * ancestry + callbacks)
pub fn recover_aer(root_bdf: pci::Bdf, status: u32, source: u32) -> Recovery {
    if status & ROOT_UNCORRECTABLE_RECEIVED == 0 { return Recovery::IgnoredCorrectable; }
    let Some(port) = super::find(root_bdf) else { return Recovery::SourceMissing; };
    let devices = drv::devices();
    let root = port.parent();
    let source = source_bdf(root_bdf.segment, source);
    let Some(source) = devices.iter().find(|dev| pci_bdf(dev) == Some(source)) else { return Recovery::SourceMissing; };
    if !descends_from(source, root, &devices) { return Recovery::SourceMissing; }
    let affected: Vec<_> = devices.iter().filter(|dev| dev.bus == "pci" && descends_from(dev, root, &devices)).cloned().collect();
    let state = if status & ROOT_FATAL_RECEIVED != 0 { drv::PciChannelState::Frozen } else { drv::PciChannelState::Normal };
    let mut result = drv::PciErsResult::CanRecover;
    for dev in &affected { result = merge(result, detected_vote(dev, state)); }
    if result == drv::PciErsResult::CanRecover {
        result = drv::PciErsResult::Recovered;
        for dev in &affected {
            if let Some(Some(vote)) = drv::with_bound_pci_error_handlers(dev, |handlers|
                handlers.mmio_enabled.map(|callback| callback(dev))) { result = merge(result, vote); }
        }
    }
    if result == drv::PciErsResult::NeedReset || state == drv::PciChannelState::Frozen {
        permanent_failure(&affected);
        return Recovery::ResetRequired;
    }
    if result != drv::PciErsResult::Recovered {
        permanent_failure(&affected);
        return Recovery::Disconnected;
    }
    for dev in &affected {
        let _ = drv::with_bound_pci_error_handlers(dev, |handlers| {
            if let Some(callback) = handlers.resume { callback(dev); }
        });
    }
    Recovery::Recovered
}

fn source_bdf(segment: u16, source: u32) -> pci::Bdf {
    let raw = (source >> ROOT_UNCORRECTABLE_SOURCE_SHIFT) as u16;
    pci::Bdf { segment, bus: (raw >> 8) as u8, device: ((raw >> 3) & 0x1f) as u8, function: (raw & 7) as u8 }
}

fn pci_bdf(dev: &drv::Device) -> Option<pci::Bdf> {
    (dev.bus == "pci").then(|| pci::parse_bdf_addr(&dev.addr)).flatten()
}

fn descends_from(dev: &Arc<drv::Device>, root: &Arc<drv::Device>, devices: &[Arc<drv::Device>]) -> bool {
    let mut current = Arc::clone(dev);
    for _ in 0..devices.len() {
        let Some((bus, addr)) = current.parent() else { return false; };
        if bus != "pci" { return false; }
        let Some(parent) = devices.iter().find(|candidate| candidate.bus == bus && candidate.addr == addr) else { return false; };
        if Arc::ptr_eq(parent, root) { return true; }
        current = Arc::clone(parent);
    }
    false
}

fn detected_vote(dev: &drv::Device, state: drv::PciChannelState) -> drv::PciErsResult {
    match drv::with_bound_pci_error_handlers(dev, |handlers| handlers.error_detected.map(|callback| callback(dev, state))) {
        Some(Some(vote)) => vote,
        _ if dev.pci.is_some_and(|ident| ident.header_type & PCI_HEADER_TYPE_MASK == PCI_HEADER_TYPE_BRIDGE) => drv::PciErsResult::None,
        _ => drv::PciErsResult::NoAerDriver,
    }
}

fn permanent_failure(affected: &[Arc<drv::Device>]) {
    for dev in affected {
        let _ = drv::with_bound_pci_error_handlers(dev, |handlers| {
            if let Some(callback) = handlers.error_detected { let _ = callback(dev, drv::PciChannelState::PermanentFailure); }
        });
    }
}

fn merge(old: drv::PciErsResult, new: drv::PciErsResult) -> drv::PciErsResult {
    if new == drv::PciErsResult::NoAerDriver { return new; }
    if new == drv::PciErsResult::None { return old; }
    match old {
        drv::PciErsResult::CanRecover | drv::PciErsResult::Recovered => new,
        drv::PciErsResult::Disconnect if new == drv::PciErsResult::NeedReset => new,
        _ => old,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, sync::Arc};
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    const LEAF_ID: u16 = 0xae11;
    static MODE: AtomicU32 = AtomicU32::new(0);
    static DETECTED: AtomicU32 = AtomicU32::new(0);
    static MMIO: AtomicU32 = AtomicU32::new(0);
    static RESUME: AtomicU32 = AtomicU32::new(0);

    fn detected(_dev: &drv::Device, state: drv::PciChannelState) -> drv::PciErsResult {
        DETECTED.fetch_or(1 << state as u8, Ordering::AcqRel);
        if MODE.load(Ordering::Acquire) == 0 { drv::PciErsResult::CanRecover } else { drv::PciErsResult::NeedReset }
    }
    fn mmio(_dev: &drv::Device) -> drv::PciErsResult { MMIO.fetch_add(1, Ordering::AcqRel); drv::PciErsResult::Recovered }
    fn resume(_dev: &drv::Device) { RESUME.fetch_add(1, Ordering::AcqRel); }
    static HANDLERS: drv::PciErrorHandlers = drv::PciErrorHandlers {
        error_detected: Some(detected), mmio_enabled: Some(mmio), slot_reset: None, resume: Some(resume),
    };
    struct Driver;
    impl drv::Driver for Driver {
        fn name(&self) -> &'static str { "pcie-aer-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.device_id == LEAF_ID }
        fn pci_error_handlers(&self) -> Option<&'static drv::PciErrorHandlers> { Some(&HANDLERS) }
    }
    static DRIVER: Driver = Driver;

    fn device(bdf: pci::Bdf, id: u16, header: u8) -> Arc<drv::Device> {
        Arc::new(drv::Device::new("pci", format(bdf), 0, id, 0)
            .with_pci_ident(drv::PciIdent { header_type: header, ..drv::PciIdent::default() }))
    }
    fn child(bdf: pci::Bdf, parent: pci::Bdf, id: u16, header: u8) -> Arc<drv::Device> {
        Arc::new(drv::Device::new("pci", format(bdf), 0, id, 0)
            .with_parent("pci", format(parent))
            .with_pci_ident(drv::PciIdent { header_type: header, ..drv::PciIdent::default() }))
    }
    fn format(bdf: pci::Bdf) -> String { alloc::format!("{:04x}:{:02x}:{:02x}.{}", bdf.segment, bdf.bus, bdf.device, bdf.function) }

    #[test]
    fn recovery_walks_the_port_subtree_and_stops_before_an_unimplemented_reset() {
        MODE.store(0, Ordering::Release);
        DETECTED.store(0, Ordering::Release);
        MMIO.store(0, Ordering::Release);
        RESUME.store(0, Ordering::Release);
        drv::register_driver(&DRIVER);
        let root_bdf = pci::Bdf { segment: 3, bus: 0, device: 1, function: 0 };
        let bridge_bdf = pci::Bdf { segment: 3, bus: 2, device: 1, function: 0 };
        let leaf_bdf = pci::Bdf { segment: 3, bus: 3, device: 2, function: 0 };
        let root = drv::try_device_add(device(root_bdf, 1, PCI_HEADER_TYPE_BRIDGE)).unwrap();
        let bridge = drv::try_device_add_with_parent(child(bridge_bdf, root_bdf, 2, PCI_HEADER_TYPE_BRIDGE), &root).unwrap();
        let leaf = drv::try_device_add_with_parent(child(leaf_bdf, bridge_bdf, LEAF_ID, 0), &bridge).unwrap();
        let port = super::super::publish(root_bdf, Arc::clone(&root), super::super::Service::Aer.bit(), [0; 5]).unwrap();
        let source = u32::from(leaf_bdf.raw()) << ROOT_UNCORRECTABLE_SOURCE_SHIFT;
        assert_eq!(recover_aer(root_bdf, ROOT_UNCORRECTABLE_RECEIVED, source), Recovery::Recovered);
        assert_ne!(DETECTED.load(Ordering::Acquire), 0);
        assert_eq!(MMIO.load(Ordering::Acquire), 1);
        assert_eq!(RESUME.load(Ordering::Acquire), 1);
        MODE.store(1, Ordering::Release);
        DETECTED.store(0, Ordering::Release);
        assert_eq!(recover_aer(root_bdf, ROOT_UNCORRECTABLE_RECEIVED | ROOT_FATAL_RECEIVED, source), Recovery::ResetRequired);
        assert_ne!(DETECTED.load(Ordering::Acquire) & (1 << drv::PciChannelState::PermanentFailure as u8), 0);
        super::super::remove(&port);
        drv::device_del(&leaf);
        drv::device_del(&bridge);
        drv::device_del(&root);
    }
}
