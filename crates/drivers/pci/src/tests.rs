use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

struct MapReader {
    m: Mutex<HashMap<(Bdf, u8), u32>>,
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
