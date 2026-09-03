use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::{FaultAccess, VmaBacking, VmaFlags};
use crate::{Error, KResult};

use super::super::AddressSpace;

impl AddressSpace {
    /// Fill a not-present PTE from the VMA backing: anonymous zero page,
    /// file/private page-cache copy, shmem direct frame, kernel frame, or PFNMAP.
    /// # SAFETY: caller supplies the live MMU implementation and valid PMM/rmap callbacks.
    /// # C: O(log N_vmas) + O(page) for copied backings.
    pub(super) unsafe fn handle_not_present<M, A, DR, SR, IR, CA, UA, MR>(
        &self,
        va: UserVirtAddr,
        access: FaultAccess,
        hhdm_offset: u64,
        install_uffd_wp: bool,
        alloc_frame: &mut A,
        dec_ref: &mut DR,
        set_rmap: &mut SR,
        inc_ref: &mut IR,
        charge_anon: &mut CA,
        uncharge_anon: &mut UA,
        mark_referenced: &mut MR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        DR: FnMut(u64),
        SR: FnMut(u64, &alloc::sync::Arc<crate::AnonVma>, u32),
        IR: FnMut(u64),
        CA: FnMut() -> KResult<()>,
        UA: FnMut(),
        // `mark_referenced(pa)` — Linux `folio_mark_accessed` on a resident
        // file page mapped into this VMA (`filemap_fault`'s trailing
        // `folio_mark_accessed`). Called ONLY when
        // `recency::vma_has_recency` says this VMA/file combination should
        // bias reclaim aging; a `POSIX_FADV_NOREUSE` file or a
        // MADV_SEQUENTIAL/MADV_RANDOM VMA skips it, matching the reference.
        MR: FnMut(u64),
    {
        // Clone the VMA then drop the read guard before File/SHARED backing I/O;
        // holding `vmas` across block sleep deadlocks peer mmap/munmap writers.
        let vma = match self.vmas.read().find_containing(va) {
            Some(v) => v.clone(),
            None    => return Err(Error::Inval),    // EFAULT upstream
        };
        if vma.flags.contains(VmaFlags::NT_RESERVED) {
            return Err(Error::Inval);
        }
        if !vma.permits(access) {
            return Err(Error::Inval);                // EFAULT upstream
        }
        let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
        if self.brk_fault_past_current(&vma, va_page) { return Err(Error::Inval); }
        // Folded into every leaf this fill publishes, so the page is protected
        // by the same store that makes it visible rather than by a second pass
        // a peer thread's write could slip between.
        let wp = if install_uffd_wp { hal::PageFlags::UFFD_WP } else { hal::PageFlags::empty() };
        // Speculative neighbour installs are suppressed while a monitor watches
        // the range: they publish ordinary leaves over addresses the monitor
        // armed, dropping barriers no fault ever touched.
        let around_ok = !crate::uffd::fault_around_disabled(vma.flags & VmaFlags::UFFD_MASK);

        match &vma.backing {
            VmaBacking::Anonymous => {
                // SAFETY: forwards the live MMU and PMM callbacks unchanged.
                unsafe { self.handle_anonymous_not_present::<M, _, _, _, _, _>(
                    va, &vma, hhdm_offset, wp, alloc_frame, dec_ref, set_rmap,
                    charge_anon, uncharge_anon,
                ) }
            }
            VmaBacking::KernelBytes { data, off: backing_off } => {
                // ELF-loader-style demand-fault path per docs/31 §4
                // step 3: copy the file-backed bytes for this page
                // into a fresh PMM frame; bytes past the slice length
                // (BSS tail of a PT_LOAD with `p_memsz > p_filesz`)
                // are zero-filled. `backing_off` lets sub-range VMAs
                // (from `clone_subrange`) start mid-Arc without
                // copying the underlying buffer.
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let vma_off = (va_page - vma.start.as_u64()) as usize;
                let off = backing_off.saturating_add(vma_off);
                let page = PAGE_SIZE_BYTES as usize;
                let data_slice: &[u8] = &data[..];
                #[cfg(feature = "debug-faultdiag")]
                if (0x1800_04000..0x1800_05000).contains(&va_page) {
                    klog::write_raw(b"[WINDOWS-PE-KBYTES] va=");
                    klog::write_hex_u64(va_page);
                    klog::write_raw(b" vma=");
                    klog::write_hex_u64(vma.start.as_u64());
                    klog::write_raw(b" backing=");
                    klog::write_hex_u64(*backing_off as u64);
                    klog::write_raw(b" off=");
                    klog::write_hex_u64(off as u64);
                    klog::write_raw(b" src=");
                    for byte in data_slice.get(off..).unwrap_or(&[]).iter().take(8) {
                        klog::write_hex_u64(*byte as u64);
                    }
                    if va_page == 0x1800_04000 {
                        klog::write_raw(b" relay_src=");
                        for byte in data_slice.get(off + 0xc35..).unwrap_or(&[]).iter().take(12) {
                            klog::write_hex_u64(*byte as u64);
                        }
                    }
                    klog::write_raw(b"\n");
                }
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at hhdm_offset+pa is mapped writable; we
                // own the full page exclusively until M::map below
                // makes it user-visible.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    if off >= data_slice.len() {
                        // Entirely BSS (past file-backed extent).
                        hal::zerotrap::trap((dst) as *const u8, (page) as usize);
                        core::ptr::write_bytes(dst, 0, page);
                    } else {
                        let avail = (data_slice.len() - off).min(page);
                        // SAFETY: src is a valid Arc<[u8]> slice covering [off..off+avail]; dst owns `page` bytes; non-overlapping.
                        core::ptr::copy_nonoverlapping(
                            data_slice.as_ptr().add(off), dst, avail,
                        );
                        if avail < page {
                            // SAFETY: dst+avail is within the freshly-allocated frame; tail zero-fills the BSS portion of this page.
                            hal::zerotrap::trap((dst.add(avail)) as *const u8, (page - avail) as usize);
                            core::ptr::write_bytes(dst.add(avail), 0, page - avail);
                        }
                    }
                    #[cfg(feature = "debug-faultdiag")]
                    if va_page == 0x1800_04000 {
                        klog::write_raw(b"[WINDOWS-PE-KBYTES-DST] bytes=");
                        for byte in core::slice::from_raw_parts(dst.add(0xc35), 12) {
                            klog::write_hex_u64(*byte as u64);
                        }
                        klog::write_raw(b"\n");
                    }
                }
                let pte_flags = vma.page_flags() | wp;
                // DIAG (debug-atexit): KernelBytes-arm install in the lib arena
                // — this arm zeros BSS tail bytes and NEVER logged before; if it
                // fires at a library VA the VMA consulted was a KernelBytes VMA
                // (exec/ld.so image) where a File VMA should be. ino=1 marks it.
                #[cfg(feature = "debug-atexit")]
                if (0x7ffff6000000..0x7ffff8000000).contains(&va_page) {
                    crate::tailwatch::log_install(b"kbytes", 1, off as u64, va_page, pa, self.root_pa);
                }
                // SAFETY: `va_page` is page-aligned and `pa` is the freshly allocated frame
                // whose BSS tail this arm just zeroed; it is unpublished and solely owned
                // here, and dropped with `dec_ref` if the install loses the race.
                let installed = unsafe {
                    self.map_if_absent::<M>(Va(va_page), Pa(pa), pte_flags, PageSize::P4K)
                };
                if !installed {
                    dec_ref(pa);
                    return Ok(());
                }
                self.accounting.install_pte(&vma);
                Ok(())
            }
            VmaBacking::File { backing, off: backing_off } => unsafe {
                self.handle_file_not_present::<M, _, _, _, _>(
                    va, access, hhdm_offset, wp, around_ok, &vma, backing, *backing_off,
                    alloc_frame, dec_ref, inc_ref, mark_referenced,
                )
            },
            VmaBacking::KernelFrame { pa } => {
                // SAFETY: same live-MMU and callback contracts as this fault fill path.
                unsafe { self.map_kernel_frame::<M, _, _>(va, &vma, *pa, dec_ref, inc_ref) }
            }
            VmaBacking::KernelPages { pages, off } => unsafe {
                self.map_kernel_pages::<M, _, _>(va, &vma, pages, *off, dec_ref, inc_ref)
            },
            VmaBacking::PhysRange { base_pa, cache } => {
                // SAFETY: same live-MMU and callback contracts as this fault fill path.
                unsafe { self.map_phys_range::<M, _>(va, &vma, *base_pa, *cache, dec_ref) }
            }
            VmaBacking::Special => Err(Error::NotImplemented),
        }
    }
}
