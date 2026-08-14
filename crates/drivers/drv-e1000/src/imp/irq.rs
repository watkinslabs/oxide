//! PCI message ownership for E1000 controller probe and teardown.

use super::*;

fn hard_msi() { let _ = hard_irq(); }

fn msix_bir(bdf: pci::Bdf) -> Option<u8> {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::pci::EcamPci::from_published().and_then(|r| pci::capabilities(&r, bdf).find(pci::CAP_ID_MSIX).and_then(|cap| pci::decode_msix_cap(&r, bdf, cap.cfg_off))).map(|cap| cap.table_bir) }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::pci::EcamPci::from_published().and_then(|r| pci::capabilities(&r, bdf).find(pci::CAP_ID_MSIX).and_then(|cap| pci::decode_msix_cap(&r, bdf, cap.cfg_off))).map(|cap| cap.table_bir) }
}

pub(super) fn bind_pci_message(parent: &Arc<drv::Device>, bdf: pci::Bdf, endpoint: usize,
    ctrl: &Controller) -> Option<(pci_irq::Binding, Option<mmio_map::Mapping>)> {
    let (table, table_map) = if msix_bir(bdf).is_none_or(|bir| bir == 0) {
        (pci_irq::BarMapping { bar: 0, base_va: ctrl.mmio.base_va(), bytes: ctrl.mmio.bytes(), offset: 0 }, None)
    } else {
        let bir = msix_bir(bdf)?;
        let resource = parent.resources.iter().find(|resource| resource.bar == bir && resource.flags & drv::IORESOURCE_MEM != 0)?;
        let bytes = resource.end.checked_sub(resource.start)?.checked_add(1)?;
        let off = resource.start & (PAGE - 1);
        let pages = off.checked_add(bytes)?.checked_add(PAGE - 1)?.checked_div(PAGE)?;
        // SAFETY: MSI-X table BAR belongs to the matched function and is retained until binding teardown.
        let map = unsafe { mmio_map::map_owned(resource.start & !(PAGE - 1), pages) };
        (pci_irq::BarMapping { bar: bir, base_va: map.base_va(), bytes: map.bytes(), offset: off }, Some(map))
    };
    let binding = pci_irq::request(bdf, table, arch_irq::DeviceAction::E1000, hard_msi)?;
    ENDPOINTS[endpoint].state.store(ENDPOINT_ACTIVE, Ordering::Release);
    Some((binding, table_map))
}

pub(super) fn release_irq(irq: pci_irq::Binding, endpoint: usize, msix: Option<mmio_map::Mapping>) {
    while ENDPOINTS[endpoint].in_handler.load(Ordering::Acquire) != 0 { core::hint::spin_loop(); }
    endpoint_release(endpoint);
    irq.release();
    drop(msix);
}
