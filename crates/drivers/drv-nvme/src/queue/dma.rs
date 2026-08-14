//! Per-command NVMe data and PRP-list DMA ownership.

use super::{hhdm, DATA_ORDER, DATA_PAGES, PAGE};

/// DMA memory retained by one live I/O command until its CQE is retired.
pub(crate) struct IoDma {
    bdf: pci::Bdf,
    data_pa: u64,
    pub(crate) data_dma: u64,
    list_pa: u64,
    pub(crate) list_dma: u64,
}

impl IoDma {
    /// Allocate and map a private command data run plus PRP-list page. # C: O(pages)
    pub(crate) fn allocate(bdf: pci::Bdf, dma_mask: u64) -> Option<Self> {
        let data_pa = if dma_mask == u64::MAX { pmm::setup::alloc_contig(DATA_ORDER) }
            else { pmm::setup::alloc_contig_below(DATA_ORDER, dma_mask.checked_add(1)?) }?;
        let data_bytes = (DATA_PAGES * PAGE) as usize;
        let Some(data_dma) = iommu::map_dma_below(bdf, data_pa, data_bytes, dma_mask) else {
            // SAFETY: mapping failed before hardware received this private data run.
            unsafe { pmm::setup::free_contig(data_pa, DATA_ORDER); }
            return None;
        };
        let Some(list_pa) = (if dma_mask == u64::MAX { pmm::setup::alloc_raw_frame() }
            else { pmm::setup::alloc_raw_frame_below(dma_mask.checked_add(1)?) }) else {
            let _ = iommu::unmap_dma(bdf, data_dma, data_bytes);
            // SAFETY: the unposted private data run has no device owner.
            unsafe { pmm::setup::free_contig(data_pa, DATA_ORDER); }
            return None;
        };
        let Some(list_dma) = iommu::map_dma_below(bdf, list_pa, PAGE as usize, dma_mask) else {
            // SAFETY: mapping failed before hardware received this private list page.
            unsafe { pmm::setup::free_one_frame(list_pa); }
            let _ = iommu::unmap_dma(bdf, data_dma, data_bytes);
            // SAFETY: the unposted private data run has no device owner.
            unsafe { pmm::setup::free_contig(data_pa, DATA_ORDER); }
            return None;
        };
        let h = hhdm();
        if h == 0 { let mut dma = Self { bdf, data_pa, data_dma, list_pa, list_dma }; dma.release(); return None; }
        // SAFETY: these freshly allocated private pages are exclusively owned before SQ publication.
        unsafe { core::ptr::write_bytes((h + list_pa) as *mut u8, 0, PAGE as usize); }
        Some(Self { bdf, data_pa, data_dma, list_pa, list_dma })
    }

    /// HHDM VA for this command's private data run. # C: O(1)
    pub(crate) fn data_va(&self) -> u64 { hhdm().wrapping_add(self.data_pa) }
    /// HHDM VA for this command's PRP-list page. # C: O(1)
    pub(crate) fn list_va(&self) -> u64 { hhdm().wrapping_add(self.list_pa) }

    /// Unmap and free this command after its CQE retired or posting failed. # C: O(pages)
    pub(crate) fn release(&mut self) {
        if self.list_pa != 0 && iommu::unmap_dma(self.bdf, self.list_dma, PAGE as usize) {
            // SAFETY: caller retired this command or never posted it to hardware.
            unsafe { pmm::setup::free_one_frame(self.list_pa); }
            self.list_pa = 0; self.list_dma = 0;
        }
        let bytes = (DATA_PAGES * PAGE) as usize;
        if self.data_pa != 0 && iommu::unmap_dma(self.bdf, self.data_dma, bytes) {
            // SAFETY: caller retired this command or never posted it to hardware.
            unsafe { pmm::setup::free_contig(self.data_pa, DATA_ORDER); }
            self.data_pa = 0; self.data_dma = 0;
        }
    }
}

impl Drop for IoDma { fn drop(&mut self) { self.release(); } }
