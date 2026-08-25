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

#[path = "pci_topology_tests.rs"]
mod topology_tests;

#[path = "pci_msix_tests.rs"]
mod msix_tests;
