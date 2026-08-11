use alloc::vec::Vec;

use crate::{AmdViPte, iova_indices};

const PAGE_BYTES: u64 = 4096;
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
    /// Map a page-aligned physical interval at an equally sized IOVA interval. # C: O(pages * levels)
    pub fn map(&mut self, iova: u64, pa: u64, len: u64) -> bool {
        if iova & (PAGE_BYTES - 1) != 0 || pa & (PAGE_BYTES - 1) != 0 || len == 0 || len & (PAGE_BYTES - 1) != 0 { return false; }
        let Some(end) = iova.checked_add(len) else { return false; };
        let mut cur_iova = iova;
        let mut cur_pa = pa;
        while cur_iova != end {
            if !self.map_page(cur_iova, cur_pa) {
                let _ = self.unmap(iova, cur_iova - iova);
                return false;
            }
            cur_iova += PAGE_BYTES;
            cur_pa += PAGE_BYTES;
        }
        true
    }
    /// Remove leaf PTEs after the IOMMU has invalidated their translations. # C: O(pages * levels)
    pub fn unmap(&mut self, iova: u64, len: u64) -> bool {
        if iova & (PAGE_BYTES - 1) != 0 || len == 0 || len & (PAGE_BYTES - 1) != 0 { return false; }
        let Some(end) = iova.checked_add(len) else { return false; };
        let mut cur = iova;
        while cur != end {
            let Some(leaf_pa) = self.leaf_entry_pa(cur) else { return false; };
            if read_entry(self.hhdm_offset, leaf_pa) & PTE_PRESENT == 0 { return false; }
            write_entry(self.hhdm_offset, leaf_pa, 0);
            cur += PAGE_BYTES;
        }
        true
    }
    fn map_page(&mut self, iova: u64, pa: u64) -> bool {
        let indices = iova_indices(iova);
        let mut table_pa = self.root_pa;
        for level in 0..3 {
            let entry_pa = table_pa + indices[level] as u64 * core::mem::size_of::<u64>() as u64;
            let entry = read_entry(self.hhdm_offset, entry_pa);
            if entry & PTE_PRESENT == 0 {
                let Some(next_pa) = allocate_table(self.hhdm_offset) else { return false; };
                let Some(pte) = AmdViPte::table(next_pa, PAGE_MODE - level as u8 - 1) else { return false; };
                write_entry(self.hhdm_offset, entry_pa, pte.word());
                self.pages.push(next_pa);
                table_pa = next_pa;
            } else {
                table_pa = entry & 0x000f_ffff_ffff_f000;
            }
        }
        let leaf_pa = table_pa + indices[3] as u64 * core::mem::size_of::<u64>() as u64;
        if read_entry(self.hhdm_offset, leaf_pa) & PTE_PRESENT != 0 { return false; }
        let Some(leaf) = AmdViPte::leaf(pa) else { return false; };
        write_entry(self.hhdm_offset, leaf_pa, leaf.word());
        true
    }
    fn leaf_entry_pa(&self, iova: u64) -> Option<u64> {
        let indices = iova_indices(iova);
        let mut table_pa = self.root_pa;
        for level in 0..3 {
            let entry_pa = table_pa + indices[level] as u64 * core::mem::size_of::<u64>() as u64;
            let entry = read_entry(self.hhdm_offset, entry_pa);
            if entry & PTE_PRESENT == 0 { return None; }
            table_pa = entry & 0x000f_ffff_ffff_f000;
        }
        Some(table_pa + indices[3] as u64 * core::mem::size_of::<u64>() as u64)
    }
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
