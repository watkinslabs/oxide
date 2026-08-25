use super::*;

#[test]
fn bridge_windows_decode_into_their_three_distinct_resource_kinds() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bdf = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    r.write32(bdf, 0x1c, 0x0000_3121);
    r.write32(bdf, 0x20, 0x4ff0_4000);
    r.write32(bdf, 0x24, 0x50f1_5001);
    r.write32(bdf, 0x28, 1);
    r.write32(bdf, 0x2c, 2);
    r.write32(bdf, 0x30, 0x0001_0001);
    let windows = bridge_window_resources(&r, bdf);
    assert_eq!(windows[0], Some(Resource { start: 0x1_2000, end: 0x1_3fff, flags: IORESOURCE_IO }));
    assert_eq!(windows[1], Some(Resource { start: 0x4000_0000, end: 0x4fff_ffff, flags: IORESOURCE_MEM }));
    assert_eq!(windows[2], Some(Resource { start: 0x1_5000_0000, end: 0x2_50ff_ffff, flags: IORESOURCE_MEM | IORESOURCE_PREFETCH }));
}

#[test]
fn enumerate_finds_one_device() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 5,
        function: 0,
    };
    r.write32(bdf, 0x00, 0x1041_1AF4);
    r.write32(bdf, 0x08, 0x0200_0000);
    r.write32(bdf, 0x0C, 0);
    let v = enumerate(&r);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].vendor_id, 0x1AF4);
    assert_eq!(v[0].device_id, 0x1041);
    assert_eq!(v[0].class_code, 0x02);
}

#[test]
fn bridge_bus_window_requires_a_live_pci_to_pci_bridge() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bdf = Bdf { segment: 3, bus: 4, device: 5, function: 0 };
    r.write32(bdf, 0x00, 0x1001_1234);
    r.write32(bdf, 0x08, 0x0604_0000);
    r.write32(bdf, 0x0C, 0x0001_0000);
    r.write32(bdf, 0x18, 0x0008_0704);
    assert_eq!(bridge_buses(&r, bdf), Some(BridgeBuses { primary: 4, secondary: 7, subordinate: 8 }));
}

#[test]
fn parent_bridge_uses_the_narrowest_unambiguous_window() {
    let root = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    let downstream = Bdf { segment: 0, bus: 4, device: 2, function: 0 };
    let child = Bdf { segment: 0, bus: 7, device: 3, function: 0 };
    let bridges = [
        (root, BridgeBuses { primary: 0, secondary: 2, subordinate: 8 }),
        (downstream, BridgeBuses { primary: 4, secondary: 6, subordinate: 7 }),
    ];
    assert_eq!(parent_bridge(&bridges, child), Some(downstream));
}

#[test]
fn parent_bridge_rejects_ambiguous_peer_windows() {
    let first = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    let second = Bdf { segment: 0, bus: 0, device: 2, function: 0 };
    let child = Bdf { segment: 0, bus: 4, device: 0, function: 0 };
    let bridges = [
        (first, BridgeBuses { primary: 0, secondary: 4, subordinate: 5 }),
        (second, BridgeBuses { primary: 0, secondary: 4, subordinate: 6 }),
    ];
    assert_eq!(parent_bridge(&bridges, child), None);
}

#[test]
fn intx_swizzle_reaches_the_root_bridge_pin() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bridge = Bdf { segment: 0, bus: 0, device: 5, function: 0 };
    let endpoint = Bdf { segment: 0, bus: 2, device: 3, function: 0 };
    r.write32(bridge, 0x00, 0x0001_1234);
    r.write32(bridge, 0x08, 0x0604_0000);
    r.write32(bridge, 0x0C, 0x0001_0000);
    r.write32(bridge, 0x18, 0x0002_0200);
    assert_eq!(swizzle_intx_to_root(&r, endpoint, 1), Some((bridge, 4)));
}

#[test]
fn enumerate_segment_uses_the_mcfg_segment_and_start_bus() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bdf = Bdf { segment: 3, bus: 0x40, device: 5, function: 0 };
    r.write32(bdf, 0x00, 0x1041_1AF4);
    r.write32(bdf, 0x08, 0x0200_0000);
    r.write32(bdf, 0x0C, 0);

    let v = enumerate_segment_buses(&r, 3, 0x40, 2);

    assert_eq!(v.len(), 1);
    assert_eq!(v[0].bdf, bdf);
}

#[test]
fn enumerate_follows_bridge_windows_only() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bridge = Bdf {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let child = Bdf {
        segment: 0,
        bus: 2,
        device: 3,
        function: 0,
    };
    let orphan = Bdf {
        segment: 0,
        bus: 4,
        device: 3,
        function: 0,
    };
    r.write32(bridge, 0x00, 0x0001_1234);
    r.write32(bridge, 0x08, 0x0604_0000);
    r.write32(bridge, 0x0C, 0x0001_0000);
    r.write32(bridge, 0x18, 0x0002_0100);
    r.write32(child, 0x00, 0x1001_1AF4);
    r.write32(child, 0x08, 0x0200_0000);
    r.write32(child, 0x0C, 0);
    r.write32(orphan, 0x00, 0x1002_1AF4);
    r.write32(orphan, 0x08, 0x0200_0000);
    r.write32(orphan, 0x0C, 0);

    let v = enumerate_buses(&r, 5);

    assert!(v.iter().any(|d| d.bdf == bridge));
    assert!(v.iter().any(|d| d.bdf == child));
    assert!(!v.iter().any(|d| d.bdf == orphan));
}

#[test]
fn enumerate_honors_bus_cap_for_bridge_windows() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bridge = Bdf {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let child = Bdf {
        segment: 0,
        bus: 2,
        device: 3,
        function: 0,
    };
    r.write32(bridge, 0x00, 0x0001_1234);
    r.write32(bridge, 0x08, 0x0604_0000);
    r.write32(bridge, 0x0C, 0x0001_0000);
    r.write32(bridge, 0x18, 0x0002_0100);
    r.write32(child, 0x00, 0x1001_1AF4);
    r.write32(child, 0x08, 0x0200_0000);
    r.write32(child, 0x0C, 0);

    let v = enumerate_buses(&r, 1);

    assert!(v.iter().any(|d| d.bdf == bridge));
    assert!(!v.iter().any(|d| d.bdf == child));
}

#[test]
fn parse_bdf_addr_kernel_model_form() {
    assert_eq!(
        parse_bdf_addr("0000:00:1f.2"),
        Some(Bdf {
        segment: 0,
            bus: 0x00,
            device: 0x1f,
            function: 2,
        })
    );
    assert_eq!(parse_bdf_addr("0003:ab:0C.7").map(|b| b.segment), Some(3));
    assert_eq!(
        parse_bdf_addr("0000:ab:0C.7"),
        Some(Bdf {
        segment: 0,
            bus: 0xab,
            device: 0x0c,
            function: 7,
        })
    );
    assert_eq!(parse_bdf_addr("00:1f.2"), None);
    assert_eq!(parse_bdf_addr("0000:00:1f:x"), None);
}

#[test]
fn enable_mem_bus_master_preserves_status_bits() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 6,
        function: 0,
    };
    r.write32(bdf, 0x04, 0x1234_0001);

    let old = enable_mem_bus_master(&r, bdf);

    assert_eq!(old, COMMAND_IO);
    assert_eq!(r.read32(bdf, 0x04), 0x1234_0007);
}

#[test]
fn enable_mem_decode_does_not_grant_bus_master() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bdf = Bdf { segment: 0, bus: 0, device: 4, function: 0 };
    r.write32(bdf, 0x04, 0xbeef_0001);
    assert_eq!(enable_mem_decode(&r, bdf), 1);
    assert_eq!(r.read32(bdf, 0x04), 0xbeef_0003);
}

#[test]
fn disable_mem_bus_master_preserves_status_bits() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 6,
        function: 0,
    };
    r.write32(bdf, 0x04, 0x1234_0007);

    let old = disable_mem_bus_master(&r, bdf);

    assert_eq!(old, COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_IO);
    assert_eq!(r.read32(bdf, 0x04), 0x1234_0001);
}

#[test]
fn clear_bus_master_preserves_io_memory_and_status_bits() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bdf = Bdf { segment: 0, bus: 0, device: 1, function: 0 };
    r.write32(bdf, 0x04, 0x1234_0007);

    let old = clear_bus_master(&r, bdf);

    assert_eq!(old, COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_IO);
    assert_eq!(r.read32(bdf, 0x04), 0x1234_0003);
}

#[test]
fn restore_mem_bus_master_restores_only_owned_bits() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 6,
        function: 1,
    };
    r.write32(bdf, 0x04, 0x1234_0007);

    let old = restore_mem_bus_master(&r, bdf, COMMAND_MEMORY);

    assert_eq!(old, COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_IO);
    assert_eq!(r.read32(bdf, 0x04), 0x1234_0003);
}

#[test]
fn decode_mem64_bar() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    r.write32(bdf, 0x10, 0x0000_000C);
    r.write32(bdf, 0x14, 0x0000_0001);
    r.write32(bdf, 0x18, 0);
    r.write32(bdf, 0x1C, 0);
    r.write32(bdf, 0x20, 0);
    r.write32(bdf, 0x24, 0);
    let bars = decode_bars(&r, bdf);
    assert_eq!(
        bars[0],
        Bar::Mem64 {
            base: 0x1_0000_0000,
            prefetch: true,
        }
    );
    assert_eq!(bars[0].mem_base(), Some(0x1_0000_0000));
    assert_eq!(bars[1], Bar::HighHalfConsumed);
    assert_eq!(bars[1].mem_base(), None);
    assert_eq!(bars[2], Bar::None);
}

#[test]
fn decode_mem32_and_io() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 2,
        function: 0,
    };
    r.write32(bdf, 0x10, 0x1000_0000);
    r.write32(bdf, 0x14, 0x0000_C001);
    r.write32(bdf, 0x18, 0);
    r.write32(bdf, 0x1C, 0);
    r.write32(bdf, 0x20, 0);
    r.write32(bdf, 0x24, 0);
    let bars = decode_bars(&r, bdf);
    assert_eq!(
        bars[0],
        Bar::Mem32 {
            base: 0x1000_0000,
            prefetch: false,
        }
    );
    assert_eq!(bars[1], Bar::Io { port: 0xC000 });
}

#[test]
fn probe_bar_resources_restores_command_and_bars() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 3,
        function: 0,
    };
    r.write32(bdf, 0x04, 0x0010_0007);
    r.write32(bdf, 0x10, 0x1000_0000);
    r.write32(bdf, 0x14, 0x0000_C001);
    r.write32(bdf, 0x18, 0);
    r.write32(bdf, 0x1C, 0);
    r.write32(bdf, 0x20, 0);
    r.write32(bdf, 0x24, 0);

    let res = probe_bar_resources(&r, bdf);

    assert_eq!(r.read32(bdf, 0x04), 0x0010_0007);
    assert_eq!(r.read32(bdf, 0x10), 0x1000_0000);
    assert_eq!(r.read32(bdf, 0x14), 0x0000_C001);
    assert_eq!(
        res[0],
        Some(Resource {
            start: 0x1000_0000,
            end: 0x1000_000f,
            flags: IORESOURCE_MEM,
        })
    );
    assert_eq!(
        res[1],
        Some(Resource {
            start: 0xC000,
            end: 0xC003,
            flags: IORESOURCE_IO,
        })
    );
}

