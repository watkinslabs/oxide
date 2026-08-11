use alloc::vec::Vec;

use crate::{Mapping, VtdContextEntry, VtdPageTable, VtdRootEntry};
use pci::{Bdf, IovaSpace};

const PAGE_BYTES: u64 = 4096;
const CONTEXT_ENTRIES: usize = 256;
const ROOT_ENTRY_BYTES: u64 = core::mem::size_of::<VtdRootEntry>() as u64;
const CONTEXT_ENTRY_BYTES: u64 = core::mem::size_of::<VtdContextEntry>() as u64;
const PRESENT: u64 = 1;
const IOVA_START: u64 = 0;
const IOVA_BYTES: u64 = 1u64 << 48;

/// Permanent VT-d root/context tables and their shared initial DMA domain.
pub struct VtdTables { hhdm_offset: u64, root_pa: u64, contexts: Vec<(u8, u64)>, space: IovaSpace, maps: Vec<Mapping>, page_table: VtdPageTable }
impl VtdTables {
    /// Allocate empty root/context ownership and a four-level DMA page-table domain. # C: O(1)
    pub fn new(hhdm_offset: u64) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let root_pa = allocate_page(hhdm_offset)?;
        Some(Self { hhdm_offset, root_pa, contexts: Vec::new(), space: IovaSpace::new(IOVA_START, IOVA_BYTES)?, maps: Vec::new(), page_table: VtdPageTable::new(hhdm_offset)? })
    }
    /// Return the physical root table address for the VT-d RTADDR register. # C: O(1)
    pub const fn root_pa(&self) -> u64 { self.root_pa }
    /// Return the hardware-selected adjusted guest address width. # C: O(1)
    pub const fn address_width(&self) -> u8 { self.page_table.address_width() }
    /// Map all PMM-owned RAM identities before attaching any PCI requester. # C: O(regions * leaves * levels)
    pub fn map_identity_regions(&mut self, regions: &[pmm::UsableRegion]) -> bool {
        for region in regions {
            if region.len_pfn == 0 { continue; }
            let Some(pa) = region.start.0.checked_shl(12) else { return false; };
            let Some(len) = region.len_pfn.checked_shl(12) else { return false; };
            if self.map_identity(pa, len).is_none() { return false; }
        }
        true
    }
    /// Map one validated firmware-reserved DMA interval before requester attachment. # C: O(leaves * levels)
    pub fn map_identity_range(&mut self, pa: u64, len: u64) -> bool { self.map_identity(pa, len).is_some() }
    /// Install one live DMA interval at a newly allocated IOVA interval. # C: O(pages * levels)
    pub fn map_dma(&mut self, pa: u64, len: u64, align: u64) -> Option<Mapping> {
        if pa & (PAGE_BYTES - 1) != 0 { return None; }
        let iova = self.space.alloc(len, align)?;
        if !self.page_table.map(iova.start, pa, iova.len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(map);
        Some(map)
    }
    /// Remove mapping PTEs but retain the interval until invalidation completes. # C: O(pages * levels)
    pub fn remove_for_invalidate(&mut self, map: Mapping) -> bool {
        self.maps.iter().any(|candidate| *candidate == map) && self.page_table.unmap(map.iova.start, map.iova.len)
    }
    /// Release a previously invalidated interval back to the VT-d IOVA allocator. # C: O(live mappings)
    pub fn release_after_invalidate(&mut self, map: Mapping) -> bool {
        let Some(index) = self.maps.iter().position(|candidate| *candidate == map) else { return false; };
        if !self.space.free(map.iova) { return false; }
        self.maps.swap_remove(index);
        true
    }
    /// Return one live mapping by its page-aligned IOVA. # C: O(live mappings)
    pub fn mapping(&self, iova: u64) -> Option<Mapping> { self.maps.iter().copied().find(|candidate| candidate.iova.start == iova) }
    /// Publish one requester context after its page-table hierarchy is fully initialized. # C: O(context buses)
    pub fn attach(&mut self, bdf: Bdf, domain_id: u16) -> bool {
        let Some(context_pa) = self.context_for_bus(bdf.bus) else { return false; };
        let devfn = (usize::from(bdf.device) << 3) | usize::from(bdf.function);
        if devfn >= CONTEXT_ENTRIES { return false; }
        let Some(context) = VtdContextEntry::translated(self.page_table.root_pa(), self.address_width(), domain_id) else { return false; };
        let [lo, hi] = context.words();
        let entry_pa = context_pa + devfn as u64 * CONTEXT_ENTRY_BYTES;
        if read64(self.hhdm_offset, entry_pa) & PRESENT != 0 { return false; }
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
    fn map_identity(&mut self, pa: u64, len: u64) -> Option<Mapping> {
        if pa & (PAGE_BYTES - 1) != 0 { return None; }
        let iova = self.space.reserve_at(pa, len)?;
        if !self.page_table.map(pa, pa, len) {
            let _ = self.space.free(iova);
            return None;
        }
        let map = Mapping { iova, pa };
        self.maps.push(map);
        Some(map)
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
