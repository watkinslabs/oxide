use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::Vma;
use crate::KResult;

use super::super::AddressSpace;

impl AddressSpace {
    /// Map a kernel-owned frame such as vvar into userspace.
    /// # SAFETY: caller supplies the live MMU implementation and valid refcount callbacks.
    /// # C: O(walk depth)
    pub(super) unsafe fn map_kernel_frame<M, DR, IR>(
        &self,
        va: UserVirtAddr,
        vma: &Vma,
        pa: u64,
        dec_ref: &mut DR,
        inc_ref: &mut IR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        DR: FnMut(u64),
        IR: FnMut(u64),
    {
        // Shared kernel frame (vvar); inc_ref balances AS-drop dec.
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        let pte_flags = vma.prot.to_page_flags();
        // SAFETY: pa is a kernel-owned frame whose lifetime exceeds every user mapping; va_page is page-aligned per find_containing; flags carry USER per `11§5`.
        // F157-A1: dec_ref any frame displaced by a stale present leaf
        // (separate from the KernelFrame's own `inc_ref(pa)` below).
        let replaced = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) };
        if replaced.is_none() { self.accounting.install_pte(vma); }
        if let Some(old) = replaced {
            // GAP-1 (displaced-frame UAF): this fault displaced a present leaf;
            // flush peer CPUs for this mm before dropping the old reference.
            hal::tlb::shootdown_others_va(va_page, self.cpumask());
            dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
        }
        inc_ref(pa);
        Ok(())
    }

    /// Map a VMA_PFNMAP-style physical device range directly into userspace.
    /// # SAFETY: caller supplies the live MMU implementation and valid refcount callback.
    /// # C: O(walk depth)
    pub(super) unsafe fn map_phys_range<M, DR>(
        &self,
        va: UserVirtAddr,
        vma: &Vma,
        base_pa: u64,
        dec_ref: &mut DR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        DR: FnMut(u64),
    {
        // Device physical range (Linux remap_pfn_range): map the page at VMA
        // offset O straight to base_pa + O. No PMM frame, no copy, no refcount.
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        let off = va_page - vma.start.as_u64();
        let pte_flags = vma.prot.to_page_flags();
        // SAFETY: base_pa+off is device memory owned by the driver; va_page is
        // page-aligned per find_containing; flags carry USER per `11§5`.
        let replaced = unsafe { M::map(Va(va_page), Pa(base_pa + off), pte_flags, PageSize::P4K) };
        if replaced.is_none() { self.accounting.install_pte(vma); }
        if let Some(old) = replaced {
            // A real PMM frame previously mapped at this VA still needs its
            // reference dropped; device PAs are ignored by the PMM callback.
            hal::tlb::shootdown_others_va(va_page, self.cpumask());
            dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
        }
        Ok(())
    }
}
