use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::Vma;
use crate::{AnonVma, Error, KResult};

use super::super::AddressSpace;

impl AddressSpace {
    /// Install a zeroed anonymous page and bind its rmap owner.
    /// # SAFETY: caller supplies the live MMU and valid PMM callbacks.
    /// # C: O(page)
    pub(super) unsafe fn handle_anonymous_not_present<M, A, DR, SR, CA, UA>(
        &self,
        va: UserVirtAddr,
        vma: &Vma,
        hhdm_offset: u64,
        uffd_wp: hal::PageFlags,
        alloc_frame: &mut A,
        dec_ref: &mut DR,
        set_rmap: &mut SR,
        charge_anon: &mut CA,
        uncharge_anon: &mut UA,
    ) -> KResult<()>
    where
        M: MmuOps,
        A: FnMut() -> Option<u64>,
        DR: FnMut(u64),
        SR: FnMut(u64, &Arc<AnonVma>, u32),
        CA: FnMut() -> KResult<()>,
        UA: FnMut(),
    {
        let av = vma.anon_vma.as_ref().ok_or(Error::Inval)?;
        charge_anon()?;
        let pa = match alloc_frame() {
            Some(pa) => pa,
            None => { uncharge_anon(); return Err(Error::NoMem); }
        };
        // SAFETY: pa is a fresh frame whose writable HHDM mirror spans one page.
        unsafe {
            let dst = (hhdm_offset + pa) as *mut u8;
            hal::zerotrap::trap(dst as *const u8, PAGE_SIZE_BYTES as usize);
            core::ptr::write_bytes(dst, 0, PAGE_SIZE_BYTES as usize);
        }
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        let pte_flags = vma.page_flags() | uffd_wp;
        #[cfg(feature = "debug-atexit")]
        if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
            crate::tailwatch::log_install(b"anon", 0, 0, va_page, pa, self.root_pa);
        }
        // A sibling can win the same first-touch while this task allocates and
        // zeroes its frame.  Preserve that page; a zero-fill must never replace
        // a live anonymous write.
        let installed = unsafe {
            self.map_if_absent::<M>(Va(va_page), Pa(pa), pte_flags, PageSize::P4K)
        };
        if !installed {
            dec_ref(pa);
            uncharge_anon();
            return Ok(());
        }
        self.accounting.install_pte(vma);
        let idx = ((va_page - vma.start.as_u64()) / PAGE_SIZE_BYTES) as u32;
        set_rmap(pa, av, idx);
        self.mark_anon_page(va)?;
        Ok(())
    }

    /// Return the VMA's anonymous-page owner, creating its canonical rmap
    /// edge at the first anonymous page install.
    /// # C: O(log N)
    pub(super) fn prepare_anon_vma(&self, va: UserVirtAddr) -> KResult<Arc<AnonVma>> {
        let mut tree = self.vmas.write();
        let vma = tree.find_containing_mut(va).ok_or(Error::Inval)?;
        if let Some(anon) = vma.anon_vma.as_ref() { return Ok(Arc::clone(anon)); }
        let anon = AnonVma::new();
        anon.attach(self.self_weak.clone(), vma.start.as_u64(), vma.end.as_u64());
        vma.anon_vma = Some(Arc::clone(&anon));
        Ok(anon)
    }
}

impl AddressSpace {
    /// Record that the mapping has acquired private anonymous data.
    /// # C: O(log N)
    pub(super) fn mark_anon_page(&self, va: UserVirtAddr) -> KResult<()> {
        let mut tree = self.vmas.write();
        let vma = tree.find_containing_mut(va).ok_or(Error::Inval)?;
        vma.anon_pages.store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }
}
