// Simulated address space: reservations with a committed prefix, counting
// every address-space operation so a workload's mapping cost is measurable.

use alloc::vec;
use alloc::vec::Vec;
use crate::backend::HeapBackend;

pub struct Region { pub base: u64, pub reserved: usize, pub committed: usize, pub bytes: Vec<u8> }

pub struct TestBackend { pub next: u64, pub regions: Vec<Region>, pub reserves: usize, pub commits: usize, pub releases: usize, pub budget: usize }

impl TestBackend {
    pub fn new() -> TestBackend { TestBackend { next: 0x1000_0000, regions: Vec::new(), reserves: 0, commits: 0, releases: 0, budget: 512 * 1024 * 1024 } }

    /// Address-space operations: what the old page-per-allocation heap paid
    /// once per `HeapAlloc`/`HeapFree` pair.
    pub fn mappings(&self) -> usize { self.reserves + self.releases }

    fn locate(&self, addr: u64, len: usize) -> Option<usize> {
        self.regions.iter().position(|region| addr >= region.base
            && addr + len as u64 <= region.base + region.committed as u64)
    }
}

impl HeapBackend for TestBackend {
    fn reserve(&mut self, size: usize) -> Option<u64> {
        if size > self.budget { return None; }
        self.budget -= size;
        let base = self.next;
        self.next += size as u64 + 0x1_0000;
        self.reserves += 1;
        self.regions.push(Region { base, reserved: size, committed: 0, bytes: vec![0u8; size] });
        Some(base)
    }
    fn commit(&mut self, base: u64, size: usize) -> bool {
        let Some(index) = self.regions.iter().position(|region| base >= region.base && base + size as u64 <= region.base + region.reserved as u64) else { return false; };
        let region = &mut self.regions[index];
        if base != region.base + region.committed as u64 { return false; }
        region.committed += size;
        self.commits += 1;
        true
    }
    fn release(&mut self, base: u64, size: usize) -> bool {
        let Some(index) = self.regions.iter().position(|region| region.base == base && region.reserved == size) else { return false; };
        self.regions.remove(index);
        self.budget += size;
        self.releases += 1;
        true
    }
    fn read(&self, addr: u64, out: &mut [u8]) -> bool {
        let Some(index) = self.locate(addr, out.len()) else { return false; };
        let start = (addr - self.regions[index].base) as usize;
        out.copy_from_slice(&self.regions[index].bytes[start..start + out.len()]);
        true
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> bool {
        let Some(index) = self.locate(addr, data.len()) else { return false; };
        let start = (addr - self.regions[index].base) as usize;
        self.regions[index].bytes[start..start + data.len()].copy_from_slice(data);
        true
    }
    fn fill(&mut self, addr: u64, len: usize, byte: u8) -> bool {
        let Some(index) = self.locate(addr, len) else { return false; };
        let start = (addr - self.regions[index].base) as usize;
        self.regions[index].bytes[start..start + len].fill(byte);
        true
    }
}
