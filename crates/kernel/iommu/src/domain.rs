use alloc::vec::Vec;

use crate::{AmdViDte, AmdViPageTable};
use pci::{Bdf, IovaRange, IovaSpace};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Mapping { pub iova: IovaRange, pub pa: u64 }

pub struct Domain { requester: Bdf, space: IovaSpace, maps: Vec<Mapping> }
impl Domain {
    /// Create one requester-bound DMA domain. # C: O(1)
    pub fn new(requester: Bdf, start: u64, len: u64) -> Option<Self> {
        Some(Self { requester, space: IovaSpace::new(start, len)?, maps: Vec::new() })
    }
    /// Requester this domain alone may attach. # C: O(1)
    pub const fn requester(&self) -> Bdf { self.requester }
    /// Reserve mapping state before backend PTE programming. # C: O(N)
    pub fn reserve(&mut self, pa: u64, len: u64, align: u64) -> Option<Mapping> {
        if pa & (pci::IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let map = Mapping { iova: self.space.alloc(len, align)?, pa };
        self.maps.push(map);
        Some(map)
    }
    /// Retire a mapping only after hardware invalidation completed. # C: O(N)
    pub fn release_after_invalidate(&mut self, map: Mapping) -> bool {
        let Some(i) = self.maps.iter().position(|m| *m == map) else { return false; };
        if !self.space.free(map.iova) { return false; }
        self.maps.swap_remove(i); true
    }
    /// Return installed mapping state for a backend PTE walk. # C: O(N)
    pub fn mapping(&self, iova: u64) -> Option<Mapping> { self.maps.iter().copied().find(|m| m.iova.start == iova) }
}

/// AMD-Vi requester domain with one hardware IOVA page-table tree.
pub struct AmdViDomain { requester: Bdf, space: IovaSpace, maps: Vec<Mapping>, page_table: AmdViPageTable }
impl AmdViDomain {
    /// Allocate one AMD-Vi domain and its empty four-level IOVA page table. # C: O(1)
    pub fn new(requester: Bdf, start: u64, len: u64, hhdm_offset: u64) -> Option<Self> {
        Some(Self { requester, space: IovaSpace::new(start, len)?, maps: Vec::new(), page_table: AmdViPageTable::new(hhdm_offset)? })
    }
    /// Requester that alone may attach this hardware domain. # C: O(1)
    pub const fn requester(&self) -> Bdf { self.requester }
    /// DTE encoding that attaches this domain's IOVA tree to its requester. # C: O(1)
    pub fn dte(&self, domain_id: u16) -> Option<AmdViDte> { AmdViDte::paging(self.page_table.root_pa(), self.page_table.page_mode(), domain_id) }
    /// Allocate IOVA space and install matching AMD-Vi leaf PTEs. # C: O(pages * levels)
    pub fn map(&mut self, pa: u64, len: u64, align: u64) -> Option<Mapping> {
        if pa & (pci::IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let iova = self.space.alloc(len, align)?;
        if !self.page_table.map(iova.start, pa, iova.len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(map);
        Some(map)
    }
    /// Install an identity mapping for one PMM-owned physical interval. # C: O(pages * levels)
    pub fn map_identity(&mut self, pa: u64, len: u64) -> Option<Mapping> {
        if pa & (pci::IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let iova = self.space.reserve_at(pa, len)?;
        if !self.page_table.map(pa, pa, len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(map);
        Some(map)
    }
    /// Retire a mapped IOVA only after its hardware invalidation completed. # C: O(pages * levels)
    pub fn release_after_invalidate(&mut self, map: Mapping) -> bool {
        let Some(index) = self.maps.iter().position(|candidate| *candidate == map) else { return false; };
        if !self.page_table.unmap(map.iova.start, map.iova.len) || !self.space.free(map.iova) { return false; }
        self.maps.swap_remove(index);
        true
    }
}

/// Return the AMD-Vi translation unit that firmware assigned this PCI requester.
/// # C: O(N)
pub fn amd_vi_unit_for_bdf(bdf: Bdf) -> Option<firmware::acpi::IommuUnit> {
    let requester = ((bdf.bus as u16) << 8) | ((bdf.device as u16) << 3) | bdf.function as u16;
    firmware::acpi::amd_vi_unit_for_requester(bdf.segment, requester)
}

#[cfg(test)] mod tests;
