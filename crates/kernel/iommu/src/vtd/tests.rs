use super::*;

struct Reader { words: [(Bdf, u8, u32); 7] }
impl ConfigSpaceReader for Reader {
    fn read32(&self, bdf: Bdf, offset: u8) -> u32 {
        self.words.iter().find(|word| word.0 == bdf && word.1 == offset).map(|word| word.2).unwrap_or(0xffff_ffff)
    }
    fn write32(&self, _bdf: Bdf, _offset: u8, _value: u32) {}
}

fn scope(scope_type: u8) -> DmarScope {
    let mut path = [0u8; firmware::acpi::MAX_DMAR_PATH_BYTES];
    path[..4].copy_from_slice(&[1, 0, 2, 0]);
    DmarScope { unit_index: 0, scope_type, enumeration_id: 0, start_bus: 0, path_len: 4, path }
}

fn bridge_scope() -> DmarScope {
    let mut path = [0u8; firmware::acpi::MAX_DMAR_PATH_BYTES];
    path[..2].copy_from_slice(&[1, 0]);
    DmarScope { unit_index: 0, scope_type: DMAR_SCOPE_BRIDGE, enumeration_id: 0, start_bus: 0, path_len: 2, path }
}

fn reader() -> Reader {
    let bridge = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    let endpoint = Bdf { segment: 0, bus: 3, device: 2, function: 0 };
    Reader { words: [
        (bridge, 0, 0x1001_1234), (bridge, 8, 0x0604_0000), (bridge, 12, 0x0001_0000), (bridge, 0x18, 0x0003_0300),
        (endpoint, 0, 0x1002_1234), (endpoint, 8, 0x0200_0000), (endpoint, 12, 0),
    ] }
}

#[test]
fn endpoint_scope_follows_each_firmware_bridge_path_hop() {
    let r = reader();
    let endpoint = Bdf { segment: 0, bus: 3, device: 2, function: 0 };
    let unit = IommuUnit { kind: firmware::acpi::IommuKind::IntelVtd, segment: 0, register_base: 0, include_all: false };
    assert_eq!(scope_target(&r, 0, scope(DMAR_SCOPE_ENDPOINT)), Some(endpoint));
    assert!(scope_matches(&r, endpoint, scope(DMAR_SCOPE_ENDPOINT), unit));
}

#[test]
fn bridge_scope_matches_a_downstream_requester_through_its_parent() {
    let r = reader();
    let endpoint = Bdf { segment: 0, bus: 3, device: 2, function: 0 };
    let unit = IommuUnit { kind: firmware::acpi::IommuKind::IntelVtd, segment: 0, register_base: 0, include_all: false };
    assert!(scope_matches(&r, endpoint, bridge_scope(), unit));
}
