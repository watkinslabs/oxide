use super::*;
use firmware::acpi::IommuKind;
use std::collections::HashMap;
use std::sync::Mutex;

struct GroupConfig { words: Mutex<HashMap<(Bdf, u16), u32>> }
impl GroupConfig { fn new() -> Self { Self { words: Mutex::new(HashMap::new()) } } }
impl ConfigSpaceReader for GroupConfig {
    fn read32(&self, bdf: Bdf, offset: u8) -> u32 { self.read32_ext(bdf, u16::from(offset)) }
    fn write32(&self, bdf: Bdf, offset: u8, value: u32) { self.write32_ext(bdf, u16::from(offset), value); }
    fn read32_ext(&self, bdf: Bdf, offset: u16) -> u32 { self.words.lock().unwrap().get(&(bdf, offset)).copied().unwrap_or(u32::MAX) }
    fn write32_ext(&self, bdf: Bdf, offset: u16, value: u32) { self.words.lock().unwrap().insert((bdf, offset), value); }
}

fn group_endpoint(config: &GroupConfig, bdf: Bdf) { config.write32(bdf, 0, 1); }
fn group_bridge(config: &GroupConfig, bdf: Bdf, secondary: u8) {
    group_endpoint(config, bdf);
    config.write32(bdf, 0x08, 0x0604_0000);
    config.write32(bdf, 0x0c, 1 << 16);
    config.write32(bdf, 0x18, (u32::from(secondary) << 8) | (u32::from(secondary) << 16));
}
fn group_acs(config: &GroupConfig, bdf: Bdf) {
    config.write32_ext(bdf, 0x100, 0x000d);
    config.write32_ext(bdf, 0x104, 0x001d_001d);
}

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

fn rmrr(segment: u16, scope: DmarScope) -> firmware::acpi::DmarRmrr {
    firmware::acpi::DmarRmrr { segment, base: 0x7f00_0000, end: 0x7f00_0fff,
        scopes: [scope; firmware::acpi::MAX_DMAR_RMRR_SCOPES], scope_count: 1 }
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
    assert_eq!(scope_target(&r, 0, scope(DMAR_SCOPE_ENDPOINT)), Some(endpoint));
    assert!(scope_matches(&r, endpoint, scope(DMAR_SCOPE_ENDPOINT), 0));
}

#[test]
fn bridge_scope_matches_a_downstream_requester_through_its_parent() {
    let r = reader();
    let endpoint = Bdf { segment: 0, bus: 3, device: 2, function: 0 };
    assert!(scope_matches(&r, endpoint, bridge_scope(), 0));
}

#[test]
fn reserved_range_follows_its_own_scope_and_segment() {
    let r = reader();
    let endpoint = Bdf { segment: 0, bus: 3, device: 2, function: 0 };
    assert!(rmrr_matches(&r, endpoint, rmrr(0, scope(DMAR_SCOPE_ENDPOINT))));
    assert!(!rmrr_matches(&r, endpoint, rmrr(1, scope(DMAR_SCOPE_ENDPOINT))));
}

#[test]
fn ioapic_scope_uses_madt_id_and_exact_pci_source_id() {
    let r = reader();
    let mut ioapic = scope(DMAR_SCOPE_IOAPIC);
    ioapic.enumeration_id = 7;
    let unit = IommuUnit { kind: IommuKind::IntelVtd, segment: 0, source_id: 0, event_msi: 0,
        register_base: 0xfed9_0000, register_pages: 1, include_all: false };
    assert_eq!(ioapic_scope_source(&r, 7, unit, ioapic), Some((unit, 0x0310)));
    assert_eq!(ioapic_scope_source(&r, 8, unit, ioapic), None);
}

#[test]
fn hpet_scope_uses_acpi_block_id_and_pci_source_id() {
    let r = reader();
    let mut hpet = scope(DMAR_SCOPE_HPET);
    hpet.enumeration_id = 3;
    let unit = IommuUnit { kind: IommuKind::IntelVtd, segment: 0, source_id: 0, event_msi: 0,
        register_base: 0xfed9_0000, register_pages: 1, include_all: false };
    assert_eq!(hpet_scope_source(&r, 3, unit, hpet), Some((unit, 0x0310)));
    assert_eq!(hpet_scope_source(&r, 4, unit, hpet), None);
}

#[test]
fn dma_groups_merge_unisolated_subtree_and_multifunction_slot() {
    let config = GroupConfig::new();
    let root = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    let child_a = Bdf { segment: 0, bus: 1, device: 0, function: 0 };
    let child_a_fn1 = Bdf { segment: 0, bus: 1, device: 0, function: 1 };
    let child_b = Bdf { segment: 0, bus: 1, device: 1, function: 0 };
    group_bridge(&config, root, 1);
    group_endpoint(&config, child_a);
    group_endpoint(&config, child_a_fn1);
    group_endpoint(&config, child_b);
    let aliases = pci::DmaAliases::new();
    assert_eq!(vtd_dma_groups(&config, &[child_a, child_b, child_a_fn1], &aliases),
        alloc::vec![alloc::vec![child_a, child_a_fn1, child_b]]);
    group_acs(&config, root);
    assert_eq!(vtd_dma_groups(&config, &[child_a, child_b, child_a_fn1], &aliases),
        alloc::vec![alloc::vec![child_a, child_a_fn1], alloc::vec![child_b]]);
}

#[test]
fn dma_groups_close_chained_explicit_aliases() {
    let config = GroupConfig::new();
    let root = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    let first = Bdf { segment: 0, bus: 1, device: 0, function: 0 };
    let second = Bdf { segment: 0, bus: 1, device: 1, function: 0 };
    let third = Bdf { segment: 0, bus: 1, device: 2, function: 0 };
    group_bridge(&config, root, 1);
    group_acs(&config, root);
    group_endpoint(&config, first);
    group_endpoint(&config, second);
    group_endpoint(&config, third);
    let mut aliases = pci::DmaAliases::new();
    assert!(aliases.add(first, second));
    assert!(aliases.add(second, third));
    assert_eq!(vtd_dma_groups(&config, &[first, second, third], &aliases),
        alloc::vec![alloc::vec![first, second, third]]);
}
