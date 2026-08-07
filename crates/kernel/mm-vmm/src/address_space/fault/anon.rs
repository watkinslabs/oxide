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
        let pte_flags = vma.page_flags();
        #[cfg(feature = "debug-atexit")]
        if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
            crate::tailwatch::log_install(b"anon", 0, 0, va_page, pa, self.root_pa);
        }
        // SAFETY: VA and PA are page-aligned and flags carry the user mapping rights.
        let replaced = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) };
        if replaced.is_none() { self.accounting.install_pte(vma); }
        if let Some(old) = replaced {
            #[cfg(feature = "debug-watchdog")]
            {
                klog::write_raw(b"[LOSTWRITE] anon-zero displaced present leaf va=");
                klog::write_hex_u64(va_page);
                klog::write_raw(b" old_pa="); klog::write_hex_u64(old.0 & !(PAGE_SIZE_BYTES - 1));
                klog::write_raw(b" newzero_pa="); klog::write_hex_u64(pa);
                klog::write_raw(b"\n");
            }
            hal::tlb::shootdown_others_va(va_page, self.cpumask());
            dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
        }
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
