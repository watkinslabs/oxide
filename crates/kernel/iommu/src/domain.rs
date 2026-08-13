use alloc::vec::Vec;

use crate::{AmdViDte, AmdViPageTable};
use pci::{Bdf, IovaRange, IovaSpace};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Mapping { pub iova: IovaRange, pub pa: u64 }

/// One DMA mapping's page-table retirement state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum MappingState { Live, IotlbPending }

/// Retains an allocated IOVA until the invalidation which makes its PTE
/// withdrawal visible to hardware has completed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct MappingRecord { pub mapping: Mapping, state: MappingState }
impl MappingRecord {
    pub(crate) const fn live(mapping: Mapping) -> Self { Self { mapping, state: MappingState::Live } }
    pub(crate) const fn iotlb_pending(self) -> bool { matches!(self.state, MappingState::IotlbPending) }
    pub(crate) fn begin_iotlb_invalidate(&mut self) -> bool {
        if self.iotlb_pending() { return false; }
        self.state = MappingState::IotlbPending;
        true
    }
}

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

/// AMD-Vi translation domain with one hardware IOVA page-table tree.
///
/// A unit may attach multiple requesters to this domain. The initial boot
/// domain deliberately covers the same identity-mapped RAM for each attached
/// requester, instead of allocating one full page-table tree per function.
pub struct AmdViDomain { space: IovaSpace, maps: Vec<MappingRecord>, page_table: AmdViPageTable }
impl AmdViDomain {
    /// Allocate one AMD-Vi domain and its empty four-level IOVA page table. # C: O(1)
    pub fn new(start: u64, len: u64, hhdm_offset: u64) -> Option<Self> {
        Some(Self { space: IovaSpace::new(start, len)?, maps: Vec::new(), page_table: AmdViPageTable::new(hhdm_offset)? })
    }
    /// DTE encoding that attaches this domain's IOVA tree to one requester. # C: O(1)
    pub fn dte(&self, domain_id: u16) -> Option<AmdViDte> { AmdViDte::paging(self.page_table.root_pa(), self.page_table.page_mode(), domain_id) }
    /// Allocate IOVA space and install matching AMD-Vi leaf PTEs. # C: O(pages * levels)
    pub fn map(&mut self, pa: u64, len: u64, align: u64) -> Option<Mapping> {
        self.map_below(pa, len, align, u64::MAX)
    }
    /// Allocate an AMD-Vi mapping whose inclusive final IOVA byte fits `mask`.
    /// # C: O(pages * levels)
    pub fn map_below(&mut self, pa: u64, len: u64, align: u64, mask: u64) -> Option<Mapping> {
        if pa & (pci::IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let iova = self.space.alloc_below(len, align, mask)?;
        if !self.page_table.map(iova.start, pa, iova.len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(MappingRecord::live(map));
        Some(map)
    }
    /// Install an identity mapping for one PMM-owned physical interval. # C: O(leaves * levels)
    pub fn map_identity(&mut self, pa: u64, len: u64) -> Option<Mapping> {
        self.map_identity_with_permissions(pa, len, true, true)
    }
    /// Install an identity map with firmware-defined device read/write permissions. # C: O(leaves * levels)
    pub fn map_identity_with_permissions(&mut self, pa: u64, len: u64, read: bool, write: bool) -> Option<Mapping> {
        if pa & (pci::IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let iova = self.space.reserve_at(pa, len)?;
        if !self.page_table.map_with_permissions(pa, pa, len, read, write) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(MappingRecord::live(map));
        Some(map)
    }
    /// Map exactly the PMM-owned RAM regions before this domain is attached. # C: O(regions * leaves * levels)
    pub fn map_identity_regions(&mut self, regions: &[pmm::UsableRegion]) -> bool {
        for region in regions {
            if region.len_pfn == 0 { continue; }
            let Some(pa) = region.start.0.checked_shl(12) else { return false; };
            let Some(len) = region.len_pfn.checked_shl(12) else { return false; };
            if self.map_identity(pa, len).is_none() { return false; }
        }
        true
    }
    /// Remove leaf PTEs while retaining IOVA ownership until hardware invalidation completes. # C: O(pages * levels)
    pub fn remove_for_invalidate(&mut self, map: Mapping) -> bool {
        let Some(index) = self.maps.iter().position(|candidate| candidate.mapping == map) else { return false; };
        if self.maps[index].iotlb_pending() { return true; }
        if !self.page_table.unmap(map.iova.start, map.iova.len) { return false; }
        self.maps[index].begin_iotlb_invalidate()
    }
    /// Return an invalidated mapping interval to the domain allocator. # C: O(N)
    pub fn release_after_invalidate(&mut self, map: Mapping) -> bool {
        let Some(index) = self.maps.iter().position(|candidate| candidate.mapping == map && candidate.iotlb_pending()) else { return false; };
        if !self.space.free(map.iova) { return false; }
        self.maps.swap_remove(index);
        true
    }
    /// Find a live mapping by its page-aligned device address. # C: O(live mappings)
    pub fn mapping(&self, iova: u64) -> Option<Mapping> { self.maps.iter().find(|candidate| candidate.mapping.iova.start == iova).map(|candidate| candidate.mapping) }
}

/// Return the AMD-Vi translation unit that firmware assigned this PCI requester.
/// # C: O(N)
pub fn amd_vi_unit_for_bdf(bdf: Bdf) -> Option<firmware::acpi::IommuUnit> {
    let requester = ((bdf.bus as u16) << 8) | ((bdf.device as u16) << 3) | bdf.function as u16;
    firmware::acpi::amd_vi_unit_for_requester(bdf.segment, requester)
}

#[cfg(test)] mod tests;
