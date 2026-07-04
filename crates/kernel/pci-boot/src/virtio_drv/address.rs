pub(super) fn bdf_word(bdf: pci::Bdf) -> u32 {
    (bdf.bus as u32) << 16 | (bdf.device as u32) << 8 | (bdf.function as u32)
}

pub(super) fn bdf_from_word(word: u32) -> pci::Bdf {
    pci::Bdf {
        bus: ((word >> 16) & 0xFF) as u8,
        device: ((word >> 8) & 0xFF) as u8,
        function: (word & 0xFF) as u8,
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

pub(super) fn parse_pci_addr(addr: &str) -> Option<pci::Bdf> {
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

pub(super) fn pci_device_from_pci_model(dev: &drv::Device) -> Option<pci::PciDevice> {
    if dev.bus != "pci" {
        return None;
    }
    pci_device_from_bdf(parse_pci_addr(&dev.addr)?)
}

pub(super) fn pci_device_from_bdf(bdf: pci::Bdf) -> Option<pci::PciDevice> {
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
