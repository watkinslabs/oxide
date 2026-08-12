//! xHCI capability-register geometry shared by controller bring-up and tests.

/// PCI class code for an xHCI USB host controller. # C: O(1)
pub const XHCI_CLASS24: u32 = 0x0c_03_30;
pub const CAPLENGTH: u64 = 0x00;
/// Interface version is the 16-bit capability-register field at byte 2. # C: O(1)
pub const HCIVERSION: u64 = 0x02;
pub const HCSPARAMS1: u64 = 0x04;
/// Capability Parameters 1 includes the context-size flag. # C: O(1)
pub const HCCPARAMS1: u64 = 0x10;
pub const DBOFF: u64 = 0x14;
pub const RTSOFF: u64 = 0x18;
pub const CAP_REGS_MIN: u64 = 0x20;
pub const REGISTER_ALIGN: u64 = 4;
pub const RUNTIME_INTR0: u64 = 0x20;
pub const DOORBELL_HOST: u8 = 0;
const EXT_CAP_ID_LEGACY: u8 = 1;
const EXT_CAP_ID_PROTOCOL: u8 = 2;
const EXT_CAP_NEXT_SHIFT: u32 = 8;
const EXT_CAP_NEXT_MASK: u32 = 0xff;
const EXT_CAP_POINTER_SHIFT: u32 = 16;
const EXT_CAP_POINTER_MASK: u32 = 0xffff;
const EXT_CAP_DWORD: u64 = 4;
const EXT_CAP_PROTOCOL_BYTES: u64 = 12;

/// One validated xHCI Supported Protocol port range. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PortProtocol { pub major: u8, pub minor: u8, pub first: u8, pub count: u8 }

impl PortProtocol {
    /// Whether this range belongs to the USB 2 root hub. # C: O(1)
    pub fn is_usb2(self) -> bool { self.major <= 2 }
}

/// Decode the three fixed dwords of a Linux `XHCI_EXT_CAPS_PROTOCOL` capability. # C: O(1)
pub fn supported_protocol(header: u32, revision: u32, ports: u32, max_ports: u8) -> Option<PortProtocol> {
    if header as u8 != EXT_CAP_ID_PROTOCOL { return None; }
    let major = (revision >> 24) as u8;
    let mut minor = (revision >> 16) as u8;
    if major == 3 && (1..16).contains(&minor) { minor <<= 4; }
    if major > 3 { return None; }
    let first = ports as u8;
    let count = (ports >> 8) as u8;
    if first == 0 || count == 0 || first.checked_add(count)?.checked_sub(1)? > max_ports { return None; }
    Some(PortProtocol { major, minor, first, count })
}

/// First extended-capability offset from HCCPARAMS1, in BAR-relative bytes. # C: O(1)
pub fn extended_capabilities(hccparams1: u32) -> u64 {
    (((hccparams1 >> EXT_CAP_POINTER_SHIFT) & EXT_CAP_POINTER_MASK) as u64) * EXT_CAP_DWORD
}

/// Find the optional USB Legacy Support capability in the xHCI extended-capability chain.
/// # C: O(BAR dwords)
pub fn legacy_capability_offset(mut read: impl FnMut(u64) -> Option<u32>, bar_bytes: u64,
                                extended_capabilities: u64) -> Option<u64> {
    let mut offset = extended_capabilities;
    if offset == 0 || offset.checked_add(EXT_CAP_DWORD)? > bar_bytes { return None; }
    for _ in 0..bar_bytes.checked_div(EXT_CAP_DWORD)? {
        let header = read(offset)?;
        if header == u32::MAX { return None; }
        if header as u8 == EXT_CAP_ID_LEGACY { return Some(offset); }
        let next = (header >> EXT_CAP_NEXT_SHIFT) & EXT_CAP_NEXT_MASK;
        if next == 0 { return None; }
        offset = offset.checked_add((next as u64) * EXT_CAP_DWORD)?;
        if offset.checked_add(EXT_CAP_DWORD)? > bar_bytes { return None; }
    }
    None
}

/// Find the protocol declaration that owns one root-hub port.
/// # C: O(BAR dwords)
pub fn protocol_for_port(mut read: impl FnMut(u64) -> Option<u32>, bar_bytes: u64, extended_capabilities: u64, max_ports: u8, port: u8) -> Option<PortProtocol> {
    if port == 0 || port > max_ports { return None; }
    let mut offset = extended_capabilities;
    if offset == 0 || offset.checked_add(EXT_CAP_DWORD)? > bar_bytes { return None; }
    let steps = bar_bytes.checked_div(EXT_CAP_DWORD)?;
    for _ in 0..steps {
        let header = read(offset)?;
        if header == u32::MAX { return None; }
        if header as u8 == EXT_CAP_ID_PROTOCOL {
            if offset.checked_add(EXT_CAP_PROTOCOL_BYTES)? > bar_bytes { return None; }
            let revision = read(offset.checked_add(EXT_CAP_DWORD)?)?;
            let ports = read(offset.checked_add(EXT_CAP_DWORD * 2)?)?;
            if let Some(protocol) = supported_protocol(header, revision, ports, max_ports) {
                if port >= protocol.first && port - protocol.first < protocol.count { return Some(protocol); }
            }
        }
        let next = (header >> EXT_CAP_NEXT_SHIFT) & EXT_CAP_NEXT_MASK;
        if next == 0 { return None; }
        offset = offset.checked_add((next as u64) * EXT_CAP_DWORD)?;
        if offset.checked_add(EXT_CAP_DWORD)? > bar_bytes { return None; }
    }
    None
}

/// Validated controller register-file locations and hardware limits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub hci_version: u16,
    pub operational: u64,
    pub runtime: u64,
    pub doorbells: u64,
    pub max_slots: u8,
    pub max_interrupters: u16,
    pub max_ports: u8,
    pub context_bytes: u8,
    pub extended_capabilities: u64,
}

/// Decode an xHCI capability block and prove later MMIO accesses remain in BAR0.
/// # C: O(1)
pub fn geometry(bar_bytes: u64, hci_version: u16, caplength: u8, hcsparams1: u32, hccparams1: u32, dboff: u32, rtsoff: u32) -> Option<Geometry> {
    let operational = caplength as u64;
    let runtime = (rtsoff as u64) & !0x1f;
    let doorbells = (dboff as u64) & !0x3;
    let max_slots = hcsparams1 as u8;
    let max_interrupters = ((hcsparams1 >> 8) & 0x07ff) as u16;
    let max_ports = (hcsparams1 >> 24) as u8;
    // Linux `HCC_64BYTE_CONTEXT`: only bit 2 selects the context stride.
    let context_bytes = if hccparams1 & (1 << 2) != 0 { 64 } else { 32 };
    if hci_version < 0x0090 || bar_bytes < CAP_REGS_MIN || operational < CAP_REGS_MIN
        || operational & (REGISTER_ALIGN - 1) != 0 || runtime < operational || runtime & 0x1f != 0
        || doorbells < operational || doorbells & (REGISTER_ALIGN - 1) != 0
        || max_slots == 0 || max_interrupters == 0 || max_ports == 0
        || runtime.checked_add(RUNTIME_INTR0 + 0x20)? > bar_bytes || doorbells.checked_add(4)? > bar_bytes
    { return None; }
    Some(Geometry { hci_version, operational, runtime, doorbells, max_slots, max_interrupters, max_ports, context_bytes, extended_capabilities: extended_capabilities(hccparams1) })
}

/// Address of one interrupter register set after capability validation. # C: O(1)
pub fn interrupter_offset(g: Geometry, index: u16) -> Option<u64> {
    if index >= g.max_interrupters { return None; }
    g.runtime.checked_add(RUNTIME_INTR0)?.checked_add((index as u64).checked_mul(0x20)?)
}

/// Address of a device or host doorbell after capability validation. # C: O(1)
pub fn doorbell_offset(g: Geometry, index: u8) -> Option<u64> {
    if index > g.max_slots { return None; }
    g.doorbells.checked_add((index as u64).checked_mul(4)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_geometry_preserves_hardware_offsets_and_limits() {
        let hcs = 64 | (8 << 8) | (12 << 24);
        let g = geometry(0x4000, 0x0100, 0x40, hcs, (1 << 2) | (16 << 16), 0x2000, 0x1000).unwrap();
        assert_eq!((g.operational, g.runtime, g.doorbells, g.max_slots, g.context_bytes), (0x40, 0x1000, 0x2000, 64, 64));
        assert_eq!(interrupter_offset(g, 7), Some(0x1100));
        assert_eq!(doorbell_offset(g, 64), Some(0x2100));
        assert_eq!(g.extended_capabilities, 0x40);
    }

    #[test]
    fn malformed_or_out_of_aperture_controller_is_rejected() {
        let hcs = 1 | (1 << 8) | (1 << 24);
        assert!(geometry(0x1000, 0x0100, 0x1f, hcs, 0, 0x200, 0x400).is_none());
        assert!(geometry(0x1000, 0x0100, 0x20, hcs, 0, 0x200, 0x1000).is_none());
        assert!(geometry(0x1000, 0x0100, 0x20, hcs, 0, 0x1000, 0x400).is_none());
        assert!(geometry(0x1000, 0x0100, 0x20, 0, 0, 0x200, 0x400).is_none());
    }

    #[test]
    fn device_doorbells_follow_the_valid_slot_range() {
        let g = Geometry { hci_version: 0x0100, operational: 0x40, runtime: 0x1000, doorbells: 0x2000, max_slots: 4, max_interrupters: 1, max_ports: 1, context_bytes: 32, extended_capabilities: 0 };
        assert_eq!(doorbell_offset(g, 1), Some(0x2004));
        assert_eq!(doorbell_offset(g, 4), Some(0x2010));
    }

    #[test]
    fn supported_protocol_uses_linux_port_range_and_usb3_minor_fixup() {
        assert_eq!(supported_protocol(2, 0x0301_0000, 2 | (4 << 8), 8), Some(PortProtocol { major: 3, minor: 0x10, first: 2, count: 4 }));
        assert!(supported_protocol(2, 0x0400_0000, 1 | (1 << 8), 8).is_none());
        assert!(supported_protocol(2, 0x0300_0000, 8 | (2 << 8), 8).is_none());
        assert!(PortProtocol { major: 2, minor: 0, first: 1, count: 1 }.is_usb2());
        assert!(!PortProtocol { major: 3, minor: 0, first: 1, count: 1 }.is_usb2());
    }

    #[test]
    fn protocol_lookup_walks_hcc_capability_chain() {
        let extended = extended_capabilities(16 << 16);
        let protocol = protocol_for_port(|offset| match offset {
            0x40 => Some(1 | (4 << EXT_CAP_NEXT_SHIFT)),
            0x50 => Some(EXT_CAP_ID_PROTOCOL as u32),
            0x54 => Some(0x0301_0000),
            0x58 => Some(2 | (4 << 8)),
            _ => None,
        }, 0x100, extended, 8, 5);
        assert_eq!(protocol, Some(PortProtocol { major: 3, minor: 0x10, first: 2, count: 4 }));
    }

    #[test]
    fn protocol_lookup_rejects_out_of_range_and_invalid_capabilities() {
        let extended = extended_capabilities(16 << 16);
        assert!(protocol_for_port(|offset| if offset == 0x40 { Some(1 | (0xff << EXT_CAP_NEXT_SHIFT)) } else { None }, 0x100, extended, 8, 1).is_none());
        assert!(protocol_for_port(|offset| match offset {
            0x40 => Some(EXT_CAP_ID_PROTOCOL as u32),
            0x44 => Some(0x0200_0000),
            0x48 => Some(8 | (2 << 8)),
            _ => None,
        }, 0x100, extended, 8, 8).is_none());
    }

    #[test]
    fn legacy_capability_walks_the_same_checked_chain() {
        let extended = extended_capabilities(16 << 16);
        assert_eq!(legacy_capability_offset(|offset| match offset {
            0x40 => Some(EXT_CAP_ID_PROTOCOL as u32 | (4 << EXT_CAP_NEXT_SHIFT)),
            0x50 => Some(EXT_CAP_ID_LEGACY as u32),
            _ => None,
        }, 0x100, extended), Some(0x50));
        assert_eq!(legacy_capability_offset(|offset| if offset == 0x40 { Some(EXT_CAP_ID_PROTOCOL as u32) } else { None }, 0x100, extended), None);
    }
}
