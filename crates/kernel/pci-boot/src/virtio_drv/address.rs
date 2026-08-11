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

fn hex_word(s: &[u8]) -> Option<u16> {
    Some(((hex_nibble(*s.first()?)? as u16) << 12) | ((hex_nibble(*s.get(1)?)? as u16) << 8)
        | ((hex_nibble(*s.get(2)?)? as u16) << 4) | hex_nibble(*s.get(3)?)? as u16)
}

pub(super) fn parse_pci_addr(addr: &str) -> Option<pci::Bdf> {
    let b = addr.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return None;
    }
    Some(pci::Bdf {
        segment: hex_word(&b[..4])?,
        bus: hex_byte(&b[5..7])?,
        device: hex_byte(&b[8..10])?,
        function: hex_nibble(b[11])?,
    })
}

pub(super) fn pci_device_from_pci_model(dev: &drv::Device) -> Option<pci::PciDevice> {
    if dev.bus != "pci" {
        return None;
    }
    pci_device_from_bdf(parse_pci_addr(&dev.addr)?)
}

pub(super) fn pci_device_from_bdf(bdf: pci::Bdf) -> Option<pci::PciDevice> {
    #[cfg(target_arch = "x86_64")]
    {
        match hal_x86_64::pci::EcamPci::from_published() {
            Some(r) => pci::PciDevice::from_config(&r, bdf),
            None => None,
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => pci::PciDevice::from_config(&r, bdf),
            None => None,
        }
    }
}
