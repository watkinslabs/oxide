use super::address::{bdf_word, parse_pci_addr, pci_device_from_pci_model};
use super::probe::{publish_transport_mmio, unpublish_transport_mmio, VirtioProbe};
use super::Arc;
use super::Vec;

struct VirtioPciDrv;
impl drv::Driver for VirtioPciDrv {
    fn name(&self) -> &'static str { "virtio-pci" }

    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "pci" && virtio::is_modern(dev.vendor_id, dev.device_id)
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let Some(d) = pci_device_from_pci_model(dev) else { return Err(drv::Error::ProbeFailed); };
        if !virtio::is_modern(d.vendor_id, d.device_id) {
            return Err(drv::Error::NoMatch);
        }

        let Some(child) = virtio::VirtioChildModelIdentity::modern_from_pci(
            d.vendor_id,
            d.device_id,
            super::super::virtio_seq(),
        ) else {
            return Err(drv::Error::NoMatch);
        };
        drv::try_device_add(Arc::new(
            drv::Device::new(
                child.bus,
                child.addr,
                child.vendor_id,
                child.device_id,
                child.class,
            )
            .with_parent("pci", dev.addr.clone()),
        ))?;
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let children: Vec<Arc<drv::Device>> = drv::devices()
            .into_iter()
            .filter(|child| virtio::virtio_child_has_parent(&child.bus, child.parent(), "pci", &dev.addr))
            .collect();
        let mut bdfs: Vec<u32> = Vec::new();
        if let Some(parent_bdf) = parse_pci_addr(&dev.addr) {
            bdfs.push(bdf_word(parent_bdf));
        }
        for child in children {
            if let Some((_, parent_addr)) = child.parent() {
                if let Some(parent_bdf) = parse_pci_addr(&parent_addr) {
                    bdfs.push(bdf_word(parent_bdf));
                }
            }
            drv::device_del(&child);
        }

        bdfs.sort_unstable();
        bdfs.dedup();
        for bdf_word in bdfs {
            unpublish_transport_mmio(bdf_word);
        }
    }

    fn shutdown(&self, dev: &drv::Device) {
        let Some(d) = pci_device_from_pci_model(dev) else { return };
        super::disable_pci_command(d.bdf);
    }
}
static VIRTIO_PCI_DRV: VirtioPciDrv = VirtioPciDrv;

#[derive(Copy, Clone, Default)]
pub(super) struct VirtioPciTransport;

impl VirtioPciTransport {
    pub(super) fn probe_child(
        self,
        d: &pci::PciDevice,
        profile: virtio::VirtioTransportProfile,
    ) -> Option<VirtioProbe> {
        if !virtio::is_modern(d.vendor_id, d.device_id) {
            return None;
        }
        super::probe::VirtioPciAcquisition::acquire(d.bdf)?.probe_child(d, profile)
    }

    pub(super) fn publish(self, p: &mut VirtioProbe) {
        publish_transport_mmio(p);
    }

    pub(super) fn unpublish_key(self, device_key: virtio::VirtioChildDeviceKey) {
        unpublish_transport_mmio(device_key.raw());
    }
}

/// Register virtio drivers whose bring-up is owned by `Driver::probe`.
/// # C: O(N_drivers)
pub(super) fn register_model_drivers() {
    drv::register_driver(&VIRTIO_PCI_DRV);
    super::super::virtio_child::register_model_drivers();
}
