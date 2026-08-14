use alloc::vec::Vec;

use crate::VtdPte;
use crate::vtd_cache::publish;

const PAGE_BYTES: u64 = 4096;
const LARGE_PAGE_BYTES: u64 = 2 * 1024 * 1024;
const HUGE_PAGE_BYTES: u64 = 1024 * 1024 * 1024;
const PTE_PRESENT: u64 = 0x3;
const PTE_LARGE_PAGE: u64 = 1 << 7;
const PTE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// VT-d second-level superpage sizes admitted by the active unit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdPageSizes { large_2m: bool, huge_1g: bool }
impl VtdPageSizes {
    /// Decode the CAP.SLLPS capability bits. # C: O(1)
    pub const fn from_sllps(bits: u8) -> Self { Self { large_2m: bits & 1 != 0, huge_1g: bits & 2 != 0 } }
    /// Return whether this unit accepts 2 MiB second-level leaves. # C: O(1)
    pub const fn large_2m(self) -> bool { self.large_2m }
    /// Return whether this unit accepts 1 GiB second-level leaves. # C: O(1)
    pub const fn huge_1g(self) -> bool { self.huge_1g }
}

/// Owned VT-d second-level identity page-table tree.
pub struct VtdPageTable { hhdm_offset: u64, coherent: bool, address_width: u8, page_sizes: VtdPageSizes, root_pa: u64, pages: Vec<u64> }
impl VtdPageTable {
    /// Allocate an empty capability-selected second-level translation tree. # C: O(1)
    pub fn new(hhdm_offset: u64, coherent: bool, address_width: u8, page_sizes: VtdPageSizes) -> Option<Self> {
        if hhdm_offset == 0 || address_width > 2 { return None; }
        let root_pa = allocate_table(hhdm_offset, coherent)?;
        Some(Self { hhdm_offset, coherent, address_width, page_sizes, root_pa, pages: alloc::vec![root_pa] })
    }
    /// Return the page-aligned context root physical address. # C: O(1)
    pub const fn root_pa(&self) -> u64 { self.root_pa }
    /// Return the VT-d adjusted guest address-width value for this four-level tree. # C: O(1)
    pub const fn address_width(&self) -> u8 { self.address_width }
    /// Map equal-sized aligned IOVA and physical ranges with largest valid leaves. # C: O(leaves * levels)
    pub fn map(&mut self, iova: u64, pa: u64, len: u64) -> bool {
        if iova & (PAGE_BYTES - 1) != 0 || pa & (PAGE_BYTES - 1) != 0 || len == 0 || len & (PAGE_BYTES - 1) != 0 { return false; }
        let Some(end) = iova.checked_add(len) else { return false; };
        let (mut current_iova, mut current_pa) = (iova, pa);
        while current_iova != end {
            let bytes = largest_page_size(current_iova, current_pa, end - current_iova, self.levels(), self.page_sizes);
            if !self.map_leaf(current_iova, current_pa, bytes) { return false; }
            current_iova += bytes;
            current_pa += bytes;
        }
        true
    }
    /// Remove an exact mapped IOVA interval while retaining table allocations. # C: O(leaves * levels)
    pub fn unmap(&mut self, iova: u64, len: u64) -> bool {
        if iova & (PAGE_BYTES - 1) != 0 || len == 0 || len & (PAGE_BYTES - 1) != 0 { return false; }
        let Some(end) = iova.checked_add(len) else { return false; };
        let mut current = iova;
        while current != end {
            let Some((leaf_pa, bytes)) = self.leaf_entry(current) else { return false; };
            if bytes > end - current || current & (bytes - 1) != 0 { return false; }
            write_entry(self.hhdm_offset, leaf_pa, 0, self.coherent);
            current += bytes;
        }
        true
    }
    fn map_leaf(&mut self, iova: u64, pa: u64, bytes: u64) -> bool {
        let depth = self.leaf_depth(bytes);
        let mut table_pa = self.root_pa;
        for level in 0..depth {
            let entry_pa = entry_pa(table_pa, self.index(iova, level));
            let entry = read_entry(self.hhdm_offset, entry_pa);
            if entry & PTE_PRESENT == 0 {
                let Some(next_pa) = allocate_table(self.hhdm_offset, self.coherent) else { return false; };
                let Some(next) = VtdPte::table(next_pa) else { return false; };
                write_entry(self.hhdm_offset, entry_pa, next.word(), self.coherent);
                self.pages.push(next_pa);
                table_pa = next_pa;
            } else {
                if entry & PTE_LARGE_PAGE != 0 {
                    let Some(next_pa) = self.split_large_leaf(level, entry_pa, entry) else { return false; };
                    table_pa = next_pa;
                } else {
                    table_pa = entry & PTE_ADDRESS_MASK;
                }
            }
        }
        let leaf_pa = entry_pa(table_pa, self.index(iova, depth));
        let prior = read_entry(self.hhdm_offset, leaf_pa);
        if prior & PTE_PRESENT != 0 { return prior & PTE_ADDRESS_MASK == pa; }
        let Some(leaf) = VtdPte::leaf(pa, bytes != PAGE_BYTES) else { return false; };
        write_entry(self.hhdm_offset, leaf_pa, leaf.word(), self.coherent);
        true
    }
    fn split_large_leaf(&mut self, level: usize, parent_pa: u64, prior: u64) -> Option<u64> {
        let parent_bytes = self.level_page_bytes(level);
        let child_bytes = self.level_page_bytes(level + 1);
        if parent_bytes == 0 || child_bytes == 0 || parent_bytes != child_bytes.checked_mul(512)? { return None; }
        let child_pa = allocate_table(self.hhdm_offset, self.coherent)?;
        let base = prior & PTE_ADDRESS_MASK;
        for index in 0..512u64 {
            let pa = base.checked_add(index.checked_mul(child_bytes)?)?;
            let leaf = VtdPte::leaf(pa, child_bytes != PAGE_BYTES)?;
            write_entry(self.hhdm_offset, entry_pa(child_pa, index as usize), leaf.word(), self.coherent);
        }
        let table = VtdPte::table(child_pa)?;
        write_entry(self.hhdm_offset, parent_pa, table.word(), self.coherent);
        self.pages.push(child_pa);
        Some(child_pa)
    }
    fn leaf_entry(&self, iova: u64) -> Option<(u64, u64)> {
        let mut table_pa = self.root_pa;
        for level in 0..self.levels() - 1 {
            let current = entry_pa(table_pa, self.index(iova, level));
            let entry = read_entry(self.hhdm_offset, current);
            if entry & PTE_PRESENT == 0 { return None; }
            if entry & PTE_LARGE_PAGE != 0 { return Some((current, self.level_page_bytes(level))); }
            table_pa = entry & PTE_ADDRESS_MASK;
        }
        let leaf_pa = entry_pa(table_pa, self.index(iova, self.levels() - 1));
        (read_entry(self.hhdm_offset, leaf_pa) & PTE_PRESENT != 0).then_some((leaf_pa, PAGE_BYTES))
    }
    const fn levels(&self) -> usize { self.address_width as usize + 2 }
    const fn index(&self, iova: u64, level: usize) -> usize {
        ((iova >> (12 + 9 * (self.levels() - 1 - level))) & 0x1ff) as usize
    }
    const fn leaf_depth(&self, bytes: u64) -> usize {
        if bytes == HUGE_PAGE_BYTES { self.levels() - 3 } else if bytes == LARGE_PAGE_BYTES { self.levels() - 2 } else { self.levels() - 1 }
    }
    const fn level_page_bytes(&self, level: usize) -> u64 { 1u64 << (12 + 9 * (self.levels() - 1 - level)) }
}

const fn largest_page_size(iova: u64, pa: u64, remaining: u64, levels: usize, page_sizes: VtdPageSizes) -> u64 {
    if levels >= 3 && page_sizes.huge_1g() && iova & (HUGE_PAGE_BYTES - 1) == 0 && pa & (HUGE_PAGE_BYTES - 1) == 0 && remaining >= HUGE_PAGE_BYTES { return HUGE_PAGE_BYTES; }
    if page_sizes.large_2m() && iova & (LARGE_PAGE_BYTES - 1) == 0 && pa & (LARGE_PAGE_BYTES - 1) == 0 && remaining >= LARGE_PAGE_BYTES { return LARGE_PAGE_BYTES; }
    PAGE_BYTES
}
const fn entry_pa(table_pa: u64, index: usize) -> u64 { table_pa + index as u64 * core::mem::size_of::<u64>() as u64 }
fn allocate_table(hhdm_offset: u64, coherent: bool) -> Option<u64> {
    let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
    // SAFETY: this one-page PMM allocation is exclusively owned by the new VT-d page table.
    unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, PAGE_BYTES as usize); }
    publish(hhdm_offset, pa, PAGE_BYTES, coherent);
    Some(pa)
}
fn read_entry(hhdm_offset: u64, pa: u64) -> u64 {
    // SAFETY: `pa` names a bounded entry in an owned VT-d page-table allocation.
    unsafe { core::ptr::read_volatile(hhdm_offset.wrapping_add(pa) as *const u64) }
}
fn write_entry(hhdm_offset: u64, pa: u64, value: u64, coherent: bool) {
    // SAFETY: `pa` names a bounded entry in an owned VT-d page-table allocation.
    unsafe { core::ptr::write_volatile(hhdm_offset.wrapping_add(pa) as *mut u64, value); }
    publish(hhdm_offset, pa, core::mem::size_of::<u64>() as u64, coherent);
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn selects_largest_aligned_vtd_identity_leaves() {
        let both = VtdPageSizes::from_sllps(3);
        assert_eq!(largest_page_size(0, 0, HUGE_PAGE_BYTES, 4, both), HUGE_PAGE_BYTES);
        assert_eq!(largest_page_size(LARGE_PAGE_BYTES, LARGE_PAGE_BYTES, LARGE_PAGE_BYTES, 4, both), LARGE_PAGE_BYTES);
        assert_eq!(largest_page_size(PAGE_BYTES, PAGE_BYTES, LARGE_PAGE_BYTES, 4, both), PAGE_BYTES);
        assert_eq!(largest_page_size(0, 0, HUGE_PAGE_BYTES, 2, both), LARGE_PAGE_BYTES);
    }
    #[test] fn leaf_selection_never_exceeds_the_hardware_page_capability() {
        assert_eq!(largest_page_size(0, 0, HUGE_PAGE_BYTES, 4, VtdPageSizes::from_sllps(0)), PAGE_BYTES);
        assert_eq!(largest_page_size(0, 0, HUGE_PAGE_BYTES, 4, VtdPageSizes::from_sllps(1)), LARGE_PAGE_BYTES);
        assert_eq!(largest_page_size(0, 0, HUGE_PAGE_BYTES, 4, VtdPageSizes::from_sllps(2)), HUGE_PAGE_BYTES);
    }
}
