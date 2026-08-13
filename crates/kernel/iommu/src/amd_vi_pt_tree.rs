use alloc::vec::Vec;

use crate::{AmdViPte, iova_indices};

const PAGE_BYTES: u64 = 4096;
const LARGE_PAGE_BYTES: u64 = 2 * 1024 * 1024;
const HUGE_PAGE_BYTES: u64 = 1024 * 1024 * 1024;
const PAGE_MODE: u8 = 4;
const PTE_PRESENT: u64 = 1;

/// Owned four-level AMD-Vi IOVA page-table tree.
pub struct AmdViPageTable { hhdm_offset: u64, root_pa: u64, pages: Vec<u64> }
impl AmdViPageTable {
    /// Allocate an empty four-level IOVA tree from the kernel PMM. # C: O(1)
    pub fn new(hhdm_offset: u64) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let root_pa = allocate_table(hhdm_offset)?;
        Some(Self { hhdm_offset, root_pa, pages: alloc::vec![root_pa] })
    }
    /// Physical root suitable for an AMD-Vi paging DTE. # C: O(1)
    pub const fn root_pa(&self) -> u64 { self.root_pa }
    /// AMD-Vi DTE page-mode value for this tree. # C: O(1)
    pub const fn page_mode(&self) -> u8 { PAGE_MODE }
    /// Map a page-aligned physical interval at an equally sized IOVA interval. # C: O(leaves * levels)
    pub fn map(&mut self, iova: u64, pa: u64, len: u64) -> bool {
        self.map_with_permissions(iova, pa, len, true, true)
    }
    /// Map a page-aligned interval with hardware read/write permission bits. # C: O(leaves * levels)
    pub fn map_with_permissions(&mut self, iova: u64, pa: u64, len: u64, read: bool, write: bool) -> bool {
        if iova & (PAGE_BYTES - 1) != 0 || pa & (PAGE_BYTES - 1) != 0 || len == 0 || len & (PAGE_BYTES - 1) != 0 { return false; }
        let Some(end) = iova.checked_add(len) else { return false; };
        let mut cur_iova = iova;
        let mut cur_pa = pa;
        while cur_iova != end {
            let page_bytes = largest_page_size(cur_iova, cur_pa, end - cur_iova);
            if !self.map_leaf(cur_iova, cur_pa, page_bytes, read, write) {
                let _ = self.unmap(iova, cur_iova - iova);
                return false;
            }
            cur_iova += page_bytes;
            cur_pa += page_bytes;
        }
        true
    }
    /// Remove leaf PTEs after the IOMMU has invalidated their translations. # C: O(leaves * levels)
    pub fn unmap(&mut self, iova: u64, len: u64) -> bool {
        if iova & (PAGE_BYTES - 1) != 0 || len == 0 || len & (PAGE_BYTES - 1) != 0 { return false; }
        let Some(end) = iova.checked_add(len) else { return false; };
        let mut cur = iova;
        while cur != end {
            let Some((leaf_pa, page_bytes)) = self.leaf_entry(cur) else { return false; };
            if page_bytes > end - cur || cur & (page_bytes - 1) != 0 { return false; }
            if read_entry(self.hhdm_offset, leaf_pa) & PTE_PRESENT == 0 { return false; }
            write_entry(self.hhdm_offset, leaf_pa, 0);
            cur += page_bytes;
        }
        true
    }
    fn map_leaf(&mut self, iova: u64, pa: u64, page_bytes: u64, read: bool, write: bool) -> bool {
        let depth = leaf_depth(page_bytes);
        let indices = iova_indices(iova);
        let mut table_pa = self.root_pa;
        for level in 0..depth {
            let entry_pa = table_pa + indices[level] as u64 * core::mem::size_of::<u64>() as u64;
            let entry = read_entry(self.hhdm_offset, entry_pa);
            if entry & PTE_PRESENT == 0 {
                let Some(next_pa) = allocate_table(self.hhdm_offset) else { return false; };
                let Some(pte) = AmdViPte::table(next_pa, PAGE_MODE - level as u8 - 1) else { return false; };
                write_entry(self.hhdm_offset, entry_pa, pte.word());
                self.pages.push(next_pa);
                table_pa = next_pa;
            } else {
                if entry & (0x7 << 9) == 0 { return false; }
                table_pa = entry & 0x000f_ffff_ffff_f000;
            }
        }
        let leaf_pa = table_pa + indices[depth] as u64 * core::mem::size_of::<u64>() as u64;
        if read_entry(self.hhdm_offset, leaf_pa) & PTE_PRESENT != 0 { return false; }
        let Some(leaf) = AmdViPte::leaf(pa, read, write) else { return false; };
        write_entry(self.hhdm_offset, leaf_pa, leaf.word());
        true
    }
    fn leaf_entry(&self, iova: u64) -> Option<(u64, u64)> {
        let indices = iova_indices(iova);
        let mut table_pa = self.root_pa;
        for level in 0..3 {
            let entry_pa = table_pa + indices[level] as u64 * core::mem::size_of::<u64>() as u64;
            let entry = read_entry(self.hhdm_offset, entry_pa);
            if entry & PTE_PRESENT == 0 { return None; }
            if level != 0 && entry & (0x7 << 9) == 0 { return Some((entry_pa, page_size_for_depth(level))); }
            table_pa = entry & 0x000f_ffff_ffff_f000;
        }
        let leaf_pa = table_pa + indices[3] as u64 * core::mem::size_of::<u64>() as u64;
        (read_entry(self.hhdm_offset, leaf_pa) & PTE_PRESENT != 0).then_some((leaf_pa, PAGE_BYTES))
    }
}

const fn largest_page_size(iova: u64, pa: u64, remaining: u64) -> u64 {
    if iova & (HUGE_PAGE_BYTES - 1) == 0 && pa & (HUGE_PAGE_BYTES - 1) == 0 && remaining >= HUGE_PAGE_BYTES { return HUGE_PAGE_BYTES; }
    if iova & (LARGE_PAGE_BYTES - 1) == 0 && pa & (LARGE_PAGE_BYTES - 1) == 0 && remaining >= LARGE_PAGE_BYTES { return LARGE_PAGE_BYTES; }
    PAGE_BYTES
}

const fn leaf_depth(page_bytes: u64) -> usize {
    if page_bytes == HUGE_PAGE_BYTES { 1 } else if page_bytes == LARGE_PAGE_BYTES { 2 } else { 3 }
}

const fn page_size_for_depth(depth: usize) -> u64 {
    if depth == 1 { HUGE_PAGE_BYTES } else if depth == 2 { LARGE_PAGE_BYTES } else { PAGE_BYTES }
}

fn allocate_table(hhdm_offset: u64) -> Option<u64> {
    let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
    // SAFETY: this one-page PMM allocation is exclusively owned by the new IOVA table.
    unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, PAGE_BYTES as usize); }
    Some(pa)
}

fn read_entry(hhdm_offset: u64, pa: u64) -> u64 {
    // SAFETY: every caller derives `pa` from an owned one-page page-table allocation and a bounded entry index.
    unsafe { core::ptr::read_volatile(hhdm_offset.wrapping_add(pa) as *const u64) }
}

fn write_entry(hhdm_offset: u64, pa: u64, entry: u64) {
    // SAFETY: every caller derives `pa` from an owned one-page page-table allocation and a bounded entry index.
    unsafe { core::ptr::write_volatile(hhdm_offset.wrapping_add(pa) as *mut u64, entry); }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn selects_the_largest_aligned_identity_leaf() {
        assert_eq!(largest_page_size(0, 0, HUGE_PAGE_BYTES), HUGE_PAGE_BYTES);
        assert_eq!(largest_page_size(LARGE_PAGE_BYTES, LARGE_PAGE_BYTES, LARGE_PAGE_BYTES), LARGE_PAGE_BYTES);
        assert_eq!(largest_page_size(PAGE_BYTES, PAGE_BYTES, LARGE_PAGE_BYTES), PAGE_BYTES);
        assert_eq!(leaf_depth(HUGE_PAGE_BYTES), 1);
        assert_eq!(page_size_for_depth(2), LARGE_PAGE_BYTES);
    }
}
