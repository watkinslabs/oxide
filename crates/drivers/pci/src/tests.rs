use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::vec;
use std::vec::Vec;

const TEST_MSIX_TABLE_ENTRIES: u16 = 4;
const TEST_MSIX_TABLE_BAR: u8 = 0;
const TEST_MSIX_TABLE_OFFSET: u32 = 0x1000;
const TEST_MSIX_LAST_ENTRY: u16 = TEST_MSIX_TABLE_ENTRIES - 1;

struct MapReader {
    m: Mutex<HashMap<(Bdf, u8), u32>>,
}

struct ReadOnlyReader {
    m: HashMap<(Bdf, u8), u32>,
    writes: std::sync::atomic::AtomicUsize,
}

impl ConfigSpaceReader for MapReader {
    fn read32(&self, bdf: Bdf, offset: u8) -> u32 {
        self.m
            .lock()
            .unwrap()
            .get(&(bdf, offset))
            .copied()
            .unwrap_or(0xFFFF_FFFF)
    }

    fn write32(&self, bdf: Bdf, offset: u8, val: u32) {
        self.m.lock().unwrap().insert((bdf, offset), val);
    }
}

impl ConfigSpaceReader for ReadOnlyReader {
    fn read32(&self, bdf: Bdf, offset: u8) -> u32 {
        self.m.get(&(bdf, offset)).copied().unwrap_or(0xFFFF_FFFF)
    }

    fn write32(&self, _bdf: Bdf, _offset: u8, _val: u32) {
        self.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn bridge_windows_decode_into_their_three_distinct_resource_kinds() {
    let r = MapReader { m: Mutex::new(HashMap::new()) };
    let bdf = Bdf { bus: 0, device: 1, function: 0 };
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
fn enumerate_follows_bridge_windows_only() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bridge = Bdf {
        bus: 0,
        device: 1,
        function: 0,
    };
    let child = Bdf {
        bus: 2,
        device: 3,
        function: 0,
    };
    let orphan = Bdf {
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
        bus: 0,
        device: 1,
        function: 0,
    };
    let child = Bdf {
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
            bus: 0x00,
            device: 0x1f,
            function: 2,
        })
    );
    assert_eq!(
        parse_bdf_addr("0000:ab:0C.7"),
        Some(Bdf {
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
fn disable_mem_bus_master_preserves_status_bits() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
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
fn restore_mem_bus_master_restores_only_owned_bits() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
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

#[test]
fn decode_msix_cap_basic() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        bus: 0,
        device: 1,
        function: 0,
    };
    r.write32(bdf, 0x40, 0x8003_0011);
    r.write32(bdf, 0x44, 0x0000_1004);
    r.write32(bdf, 0x48, 0x0000_2004);
    let m = decode_msix_cap(&r, bdf, 0x40).unwrap();
    assert!(m.enabled);
    assert!(!m.function_mask);
    assert_eq!(m.table_size, 4);
    assert_eq!(m.table_bir, 4);
    assert_eq!(m.table_offset, 0x1000);
    assert_eq!(m.pba_bir, 4);
    assert_eq!(m.pba_offset, 0x2000);
}

#[test]
fn msix_table_entry_offset_accepts_decoded_table_range() {
    let m = MsixCap {
        enabled: false,
        function_mask: false,
        table_size: TEST_MSIX_TABLE_ENTRIES,
        table_bir: TEST_MSIX_TABLE_BAR,
        table_offset: TEST_MSIX_TABLE_OFFSET,
        pba_bir: TEST_MSIX_TABLE_BAR,
        pba_offset: 0,
    };

    assert_eq!(msix_table_entry_offset(m, 0), Some(TEST_MSIX_TABLE_OFFSET as u64));
    assert_eq!(
        msix_table_entry_offset(m, TEST_MSIX_LAST_ENTRY),
        Some(TEST_MSIX_TABLE_OFFSET as u64 + (TEST_MSIX_LAST_ENTRY as u64) * MSIX_TABLE_ENTRY_BYTES)
    );
}

#[test]
fn msix_table_entry_offset_rejects_entries_outside_decoded_size() {
    let m = MsixCap {
        enabled: false,
        function_mask: false,
        table_size: TEST_MSIX_TABLE_ENTRIES,
        table_bir: TEST_MSIX_TABLE_BAR,
        table_offset: TEST_MSIX_TABLE_OFFSET,
        pba_bir: TEST_MSIX_TABLE_BAR,
        pba_offset: 0,
    };

    assert_eq!(msix_table_entry_offset(m, m.table_size), None);
    assert_eq!(msix_table_entry_offset(m, m.table_size + 1), None);
}

#[test]
fn capability_walk_and_msix_decode_do_not_write_config_space() {
    let bdf = Bdf {
        bus: 0,
        device: 1,
        function: 0,
    };
    let mut m = HashMap::new();
    m.insert((bdf, 0x04), 0x0010_0000);
    m.insert((bdf, 0x34), 0x0000_0040);
    m.insert((bdf, 0x40), 0xC003_0011);
    m.insert((bdf, 0x44), 0x0000_1004);
    m.insert((bdf, 0x48), 0x0000_2004);
    let r = ReadOnlyReader {
        m,
        writes: std::sync::atomic::AtomicUsize::new(0),
    };

    let caps = capabilities(&r, bdf);
    assert_eq!(caps.find(CAP_ID_MSIX).map(|c| c.cfg_off), Some(0x40));
    let msix = decode_msix_cap(&r, bdf, 0x40).expect("msix cap");
    assert!(msix.enabled);
    assert!(msix.function_mask);
    assert_eq!(r.writes.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn msix_control_value_clears_function_mask_when_enabling() {
    let cur = MSIX_FUNCTION_MASK | 0x03;

    assert_eq!(msix_control_value(cur, true), MSIX_ENABLE | 0x03);
    assert_eq!(
        msix_control_value(MSIX_ENABLE | 0x03, false),
        MSIX_FUNCTION_MASK | 0x03
    );
}

#[test]
fn msix_control_enable_masked_sets_enable_and_function_mask() {
    let cur = 0x03;

    assert_eq!(
        msix_control_enable_masked(cur),
        MSIX_ENABLE | MSIX_FUNCTION_MASK | 0x03
    );
}

#[test]
fn msix_teardown_masks_all_entries_before_disabling_function_and_command() {
    let mut steps = Vec::new();

    emit_msix_teardown_steps(3, |step| steps.push(step));

    assert_eq!(
        steps,
        vec![
            MsixTeardownStep::MaskEntry(0),
            MsixTeardownStep::MaskEntry(1),
            MsixTeardownStep::MaskEntry(2),
            MsixTeardownStep::DisableFunction,
            MsixTeardownStep::DisableMemBusMaster,
        ]
    );
}

#[test]
fn msix_teardown_without_entries_only_drops_command_decode() {
    let mut steps = Vec::new();

    emit_msix_teardown_steps(0, |step| steps.push(step));

    assert_eq!(steps, vec![MsixTeardownStep::DisableMemBusMaster]);
}

#[test]
fn decode_msix_cap_rejects_non_msix() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        bus: 0,
        device: 1,
        function: 0,
    };
    r.write32(bdf, 0x40, 0x0000_0009);
    assert!(decode_msix_cap(&r, bdf, 0x40).is_none());
}

#[test]
fn empty_bus_returns_nothing() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let v = enumerate(&r);
    assert!(v.is_empty());
}
