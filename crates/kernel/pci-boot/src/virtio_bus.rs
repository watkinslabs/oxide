//! Virtio bus-facing child probe boundary.
//!
//! The implementation is still backed by the boot virtio-pci transport, but
//! child model drivers enter through this module instead of reaching into the
//! PCI transport driver internals directly.

use super::virtio_drv;

pub(super) struct VirtioChildSession {
    bdf: pci::Bdf,
    transport: virtio_drv::VirtioPciTransport,
    profile: virtio::VirtioTransportProfile,
    probe: virtio_drv::VirtioProbe,
}

impl VirtioChildSession {
    pub(super) fn begin(
        dev: &drv::Device,
        profile: virtio::VirtioTransportProfile,
    ) -> drv::KResult<Self> {
        let d = pci_device_from_child(dev).ok_or(drv::Error::ProbeFailed)?;
        let transport = virtio_drv::VirtioPciTransport;
        let probe = transport
            .probe_child(&d, profile)
            .ok_or(drv::Error::ProbeFailed)?;
        super::virtio_trace::trace_probe(d.bdf, &probe.trace);
        Ok(Self {
            bdf: d.bdf,
            transport,
            profile,
            probe,
        })
    }

    pub(super) fn fail<T>(&mut self) -> drv::KResult<T> {
        virtio::VirtioChildTransportSession::release_failed_child(self);
        Err(drv::Error::ProbeFailed)
    }
}

impl virtio::VirtioChildTransportSession for VirtioChildSession {
    fn device_key(&self) -> u32 { bdf_word(self.bdf) }

    fn location(&self) -> virtio::VirtioTransportLocation {
        virtio::VirtioTransportLocation::new(self.bdf.bus, self.bdf.device, self.bdf.function)
    }

    fn drv_features(&self) -> u64 { self.probe.child_facts.drv_features }

    fn net_boot_payloads(&self) -> virtio::VirtioNetBootPayloads {
        self.probe.child_facts.net_boot_payloads()
    }

    fn child_resources(&self) -> Option<virtio::VirtioResources> {
        self.probe.child_resources(self.profile.child_requirements)
    }

    fn release_failed_child(&mut self) {
        self.probe
            .release_failed_child(self.profile.child_requirements);
    }

    fn publish(mut self) {
        self.transport.publish(&mut self.probe);
    }
}

pub(super) fn bdf_word(bdf: pci::Bdf) -> u32 {
    (bdf.bus as u32) << 16 | (bdf.device as u32) << 8 | (bdf.function as u32)
}

pub(super) fn parent_bdf(dev: &drv::Device) -> Option<pci::Bdf> {
    let (bus, addr) = dev.parent()?;
    if bus != "pci" {
        return None;
    }
    parse_pci_addr(addr)
}

pub(super) fn parent_key(dev: &drv::Device) -> Option<u32> {
    parent_bdf(dev).map(bdf_word)
}

pub(super) fn unpublish_transport(device_key: u32) {
    virtio_drv::VirtioPciTransport.unpublish_key(device_key);
}

fn pci_device_from_child(dev: &drv::Device) -> Option<pci::PciDevice> {
    pci_device_from_bdf(parent_bdf(dev)?)
}

fn pci_device_from_bdf(bdf: pci::Bdf) -> Option<pci::PciDevice> {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        pci::PciDevice::from_config(&r, bdf)
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => pci::PciDevice::from_config(&r, bdf),
            None => None,
        }
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(s: &[u8]) -> Option<u8> {
    Some((hex_nibble(*s.first()?)? << 4) | hex_nibble(*s.get(1)?)?)
}

fn parse_pci_addr(addr: &str) -> Option<pci::Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(pci::Bdf {
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}
