use alloc::vec::Vec;

use crate::{Mapping, VtdContextEntry, VtdPageTable, VtdRootEntry};
use crate::domain::MappingRecord;
use pci::{Bdf, IovaSpace};

const PAGE_BYTES: u64 = 4096;
const CONTEXT_ENTRIES: usize = 256;
const ROOT_ENTRY_BYTES: u64 = core::mem::size_of::<VtdRootEntry>() as u64;
const CONTEXT_ENTRY_BYTES: u64 = core::mem::size_of::<VtdContextEntry>() as u64;
const PRESENT: u64 = 1;
const IOVA_START: u64 = 0;
const IOVA_BYTES: u64 = 1u64 << 48;

struct VtdDomain { id: u16, requesters: Vec<Bdf>, space: IovaSpace, maps: Vec<MappingRecord>, page_table: VtdPageTable }

/// Permanent VT-d root/context tables and DMA domains selected by isolation group.
pub struct VtdTables { hhdm_offset: u64, root_pa: u64, contexts: Vec<(u8, u64)>, domains: Vec<VtdDomain> }
impl VtdTables {
    /// Allocate empty root/context ownership. # C: O(1)
    pub fn new(hhdm_offset: u64) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let root_pa = allocate_page(hhdm_offset)?;
        Some(Self { hhdm_offset, root_pa, contexts: Vec::new(), domains: Vec::new() })
    }
    /// Return the physical root table address for the VT-d RTADDR register. # C: O(1)
    pub const fn root_pa(&self) -> u64 { self.root_pa }
    /// Return the hardware-selected adjusted guest address width. # C: O(1)
    pub const fn address_width(&self) -> u8 { 2 }
    /// Create one isolated DMA domain and populate its RAM identity mappings. # C: O(regions * leaves * levels)
    pub fn install_group(&mut self, id: u16, requesters: &[Bdf], regions: &[pmm::UsableRegion]) -> bool {
        if id == 0 || requesters.is_empty() || self.domains.iter().any(|domain| domain.id == id || requesters.iter().any(|bdf| domain.requesters.contains(bdf))) { return false; }
        let Some(mut domain) = VtdDomain::new(id, requesters, self.hhdm_offset) else { return false; };
        if !domain.map_identity_regions(regions) { return false; }
        self.domains.push(domain);
        true
    }
    /// Map one validated firmware-reserved DMA interval into the requester group. # C: O(leaves * levels)
    pub fn map_identity_range(&mut self, requester: Bdf, pa: u64, len: u64) -> bool {
        self.domain_mut(requester).is_some_and(|domain| domain.map_identity(pa, len).is_some())
    }
    fn domain_mut(&mut self, requester: Bdf) -> Option<&mut VtdDomain> {
        self.domains.iter_mut().find(|domain| domain.requesters.contains(&requester))
    }
    fn domain(&self, requester: Bdf) -> Option<&VtdDomain> {
        self.domains.iter().find(|domain| domain.requesters.contains(&requester))
    }
}
impl VtdDomain {
    fn new(id: u16, requesters: &[Bdf], hhdm_offset: u64) -> Option<Self> {
        Some(Self { id, requesters: requesters.to_vec(), space: IovaSpace::new(IOVA_START, IOVA_BYTES)?, maps: Vec::new(), page_table: VtdPageTable::new(hhdm_offset)? })
    }
    fn map_identity_regions(&mut self, regions: &[pmm::UsableRegion]) -> bool {
        for region in regions {
            if region.len_pfn == 0 { continue; }
            let Some(pa) = region.start.0.checked_shl(12) else { return false; };
            let Some(len) = region.len_pfn.checked_shl(12) else { return false; };
            if self.map_identity(pa, len).is_none() { return false; }
        }
        true
    }
    fn map_dma_below(&mut self, pa: u64, len: u64, align: u64, mask: u64) -> Option<Mapping> {
        if pa & (PAGE_BYTES - 1) != 0 { return None; }
        let iova = self.space.alloc_below(len, align, mask)?;
        if !self.page_table.map(iova.start, pa, iova.len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(MappingRecord::live(map));
        Some(map)
    }
    fn remove_for_invalidate(&mut self, map: Mapping) -> bool {
        let Some(index) = self.maps.iter().position(|candidate| candidate.mapping == map) else { return false; };
        if self.maps[index].iotlb_pending() { return true; }
        if !self.page_table.unmap(map.iova.start, map.iova.len) { return false; }
        self.maps[index].begin_iotlb_invalidate()
    }
    fn release_after_invalidate(&mut self, map: Mapping) -> bool {
        let Some(index) = self.maps.iter().position(|candidate| candidate.mapping == map && candidate.iotlb_pending()) else { return false; };
        if !self.space.free(map.iova) { return false; }
        self.maps.swap_remove(index);
        true
    }
    fn mapping(&self, iova: u64) -> Option<Mapping> { self.maps.iter().find(|candidate| candidate.mapping.iova.start == iova).map(|candidate| candidate.mapping) }
    fn map_identity(&mut self, pa: u64, len: u64) -> Option<Mapping> {
        if pa & (PAGE_BYTES - 1) != 0 { return None; }
        if let Some(map) = self.maps.iter().find(|candidate| candidate.mapping.iova.start == pa
            && candidate.mapping.iova.len == len && candidate.mapping.pa == pa) { return Some(map.mapping); }
        let iova = self.space.reserve_at(pa, len)?;
        if !self.page_table.map(pa, pa, len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(MappingRecord::live(map));
        Some(map)
    }
}
impl VtdTables {
    /// Install one live DMA interval in the requester's isolation domain. # C: O(pages * levels)
    pub fn map_dma_below(&mut self, requester: Bdf, pa: u64, len: u64, align: u64, mask: u64) -> Option<Mapping> {
        self.domain_mut(requester)?.map_dma_below(pa, len, align, mask)
    }
    /// Remove one live DMA interval in the requester's isolation domain. # C: O(pages * levels)
    pub fn remove_for_invalidate(&mut self, requester: Bdf, map: Mapping) -> bool { self.domain_mut(requester).is_some_and(|domain| domain.remove_for_invalidate(map)) }
    /// Release one invalidated DMA interval in the requester's isolation domain. # C: O(live mappings)
    pub fn release_after_invalidate(&mut self, requester: Bdf, map: Mapping) -> bool { self.domain_mut(requester).is_some_and(|domain| domain.release_after_invalidate(map)) }
    /// Return one live mapping in the requester's isolation domain. # C: O(live mappings)
    pub fn mapping(&self, requester: Bdf, iova: u64) -> Option<Mapping> { self.domain(requester)?.mapping(iova) }
    /// Publish one requester context after every mapping in its isolation domain is ready. # C: O(context buses)
    pub fn attach_requester(&mut self, bdf: Bdf) -> bool {
        let Some((root_pa, address_width, domain_id)) = self.domain(bdf).map(|domain|
            (domain.page_table.root_pa(), domain.page_table.address_width(), domain.id)) else { return false; };
        self.attach(bdf, root_pa, address_width, domain_id)
    }
    /// Attach a translated requester ID to its owner's completed DMA domain.
    /// # C: O(context buses)
    pub fn attach_alias(&mut self, requester: Bdf, alias: Bdf) -> bool {
        if requester.segment != alias.segment || requester == alias { return true; }
        let Some((root_pa, address_width, domain_id)) = self.domain(requester).map(|domain|
            (domain.page_table.root_pa(), domain.page_table.address_width(), domain.id)) else { return false; };
        self.attach(alias, root_pa, address_width, domain_id)
    }
    fn attach(&mut self, bdf: Bdf, root_pa: u64, address_width: u8, domain_id: u16) -> bool {
        let Some(context_pa) = self.context_for_bus(bdf.bus) else { return false; };
        let devfn = (usize::from(bdf.device) << 3) | usize::from(bdf.function);
        if devfn >= CONTEXT_ENTRIES { return false; }
        let Some(context) = VtdContextEntry::translated(root_pa, address_width, domain_id) else { return false; };
        let [lo, hi] = context.words();
        let entry_pa = context_pa + devfn as u64 * CONTEXT_ENTRY_BYTES;
        let old_lo = read64(self.hhdm_offset, entry_pa);
        if old_lo & PRESENT != 0 {
            return old_lo == lo && read64(self.hhdm_offset, entry_pa + core::mem::size_of::<u64>() as u64) == hi;
        }
        write64(self.hhdm_offset, entry_pa + core::mem::size_of::<u64>() as u64, hi);
        write64(self.hhdm_offset, entry_pa, lo & !PRESENT);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        write64(self.hhdm_offset, entry_pa, lo);
        true
    }
    fn context_for_bus(&mut self, bus: u8) -> Option<u64> {
        if let Some((_, pa)) = self.contexts.iter().find(|(current, _)| *current == bus) { return Some(*pa); }
        let context_pa = allocate_page(self.hhdm_offset)?;
        let root = VtdRootEntry::context_table(context_pa)?;
        let [lo, hi] = root.words();
        let entry_pa = self.root_pa + u64::from(bus) * ROOT_ENTRY_BYTES;
        write64(self.hhdm_offset, entry_pa + core::mem::size_of::<u64>() as u64, hi);
        write64(self.hhdm_offset, entry_pa, lo);
        self.contexts.push((bus, context_pa));
        Some(context_pa)
    }
}

fn allocate_page(hhdm_offset: u64) -> Option<u64> {
    let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
    // SAFETY: this permanent IOMMU table page is exclusively owned by VtdTables.
    unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, PAGE_BYTES as usize); }
    Some(pa)
}
fn read64(hhdm_offset: u64, pa: u64) -> u64 {
    // SAFETY: `pa` is a bounded word inside an owned VT-d root or context table page.
    unsafe { core::ptr::read_volatile(hhdm_offset.wrapping_add(pa) as *const u64) }
}
fn write64(hhdm_offset: u64, pa: u64, value: u64) {
    // SAFETY: `pa` is a bounded word inside an owned VT-d root or context table page.
    unsafe { core::ptr::write_volatile(hhdm_offset.wrapping_add(pa) as *mut u64, value); }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn context_index_is_the_pci_device_function_number() {
        let bdf = Bdf { segment: 0, bus: 1, device: 31, function: 7 };
        assert_eq!((usize::from(bdf.device) << 3) | usize::from(bdf.function), 255);
        assert_eq!(CONTEXT_ENTRIES * core::mem::size_of::<VtdContextEntry>(), PAGE_BYTES as usize);
    }
}
