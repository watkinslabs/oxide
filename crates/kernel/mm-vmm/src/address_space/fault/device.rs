use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::{PhysCacheMode, vma::Vma};
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
        _dec_ref: &mut DR,
        inc_ref: &mut IR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        DR: FnMut(u64),
        IR: FnMut(u64),
    {
        // Shared kernel frame (vvar, io_uring ring, aio completion ring);
        // inc_ref balances AS-drop dec. `pa` names the FIRST frame of a
        // physically contiguous, refcounted run, so the page at VMA offset O
        // is `pa + O` — a single-page region is the O == 0 case. Ignoring the
        // offset would alias every page of a multi-page ring onto its header.
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        let pa = pa + (va_page - vma.start.as_u64());
        let pte_flags = vma.page_flags();
        // SAFETY: `va_page` is page-aligned and `pa` is the offset-adjusted frame of a
        // physically contiguous refcounted run whose owner keeps it alive for the life
        // of this VMA; `inc_ref` below balances the AS-drop decrement once installed.
        let installed = unsafe {
            self.map_if_absent::<M>(Va(va_page), Pa(pa), pte_flags, PageSize::P4K)
        };
        if !installed { return Ok(()); }
        self.accounting.install_pte(vma);
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
        cache: PhysCacheMode,
        _dec_ref: &mut DR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        DR: FnMut(u64),
    {
        // Device physical range (Linux remap_pfn_range): map the page at VMA
        // offset O straight to base_pa + O. No PMM frame, no copy, no refcount.
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        let off = va_page - vma.start.as_u64();
        let mut pte_flags = vma.page_flags();
        match cache {
            PhysCacheMode::WriteBack => {}
            PhysCacheMode::WriteCombine => pte_flags |= hal::PageFlags::WRITE_COMBINE,
            PhysCacheMode::Device => {
                pte_flags |= hal::PageFlags::NO_CACHE | hal::PageFlags::WRITE_THROUGH;
            }
        }
        // SAFETY: `va_page` is page-aligned and `base_pa + off` stays inside the device
        // aperture the VMA was created over, which is unrefcounted MMIO owned by the
        // driver for as long as the mapping exists, so there is no frame lifetime here.
        let installed = unsafe {
            self.map_if_absent::<M>(Va(va_page), Pa(base_pa + off), pte_flags, PageSize::P4K)
        };
        if installed { self.accounting.install_pte(vma); }
        Ok(())
    }
}
