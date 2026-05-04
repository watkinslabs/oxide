// Per-process address space per `11§3` + `11§9`.
//
// Wraps `VmaTree` in a `RwLock` (class `AddressSpace` per `06§3.6`).
// `mmap` / `munmap` / `mprotect` execute under the write lock; lookup
// (`find_vma`) takes the read lock so multiple page-fault handlers can
// run concurrently once that path lands.
//
// v1 scope:
// - anonymous + file-placeholder backings (no `Arc<File>` — VFS not
//   yet frozen at the impl level)
// - hint + `fixed` mmap flag (MAP_FIXED-equivalent: clear overlap then
//   place); without `fixed`, hint is advisory and we fall back to
//   first-fit hole search
// - per-AS PT spinlock + page-fault handler + COW + TLB shootdown all
//   land in subsequent P1-N branches alongside HAL `MmuOps`.

use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES, USER_VA_END};
use sync::{AddressSpace as AddressSpaceClass, RwLock, RwReadGuard};

use crate::tree::VmaTree;
use crate::vma::{FaultAccess, FaultKind, Vma, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

/// Lowest user VA this allocator hands out. Page 0 is reserved as the
/// canonical null-pointer trap region per `11§4` (`USER_VA_END` upper
/// bound is in `01§1`).
pub const MIN_USER_VA: u64 = PAGE_SIZE_BYTES;

/// Per-process AS. Public surface mirrors `11§3`. The Page Table side
/// (`11§9`) lives in `root_pa`: the PA of this AS's top-level table
/// (PML4 on x86_64; L0 on aarch64). `MmuOps::activate(root_pa)`
/// installs it as the active CR3 / TTBR0_EL1 per `13§8`.
pub struct AddressSpace {
    vmas:    RwLock<VmaTree, AddressSpaceClass>,
    root_pa: u64,
}

impl AddressSpace {
    /// Construct an empty AS over the page-table root at `root_pa`,
    /// returning a reference-counted handle so `fork` can share VMA-
    /// tree state once COW is wired (`11§7`).
    ///
    /// `root_pa` is the PA of the top-level page-table frame this AS
    /// owns: PML4 (x86_64, kernel-half cloned from the master per
    /// `11§2` invariant 5) or L0 (aarch64, user-half only — kernel
    /// rides TTBR1_EL1 unchanged). Production callers obtain it via
    /// `hal_<arch>::mmu_ops::new_user_pml4` / `::new_user_l0`. The
    /// `0` sentinel is reserved for hosted tests that exercise only
    /// VMA-tree behaviour and never activate the AS.
    /// # C: O(1)
    pub fn new(root_pa: u64) -> KResult<Arc<Self>> {
        Ok(Arc::new(Self {
            vmas: RwLock::new(VmaTree::new()),
            root_pa,
        }))
    }

    /// PA of this AS's top-level page-table frame. Pass to
    /// `MmuOps::activate` to make this AS the live address space.
    /// `0` for hosted-test stub ASes.
    /// # C: O(1)
    pub fn root_pa(&self) -> u64 { self.root_pa }

    /// Clone this AS's VMA tree into a new AS with the supplied
    /// PT root PA. Mapped pages are NOT copied — child PT entries
    /// start empty; first user access demand-pages from
    /// KernelBytes (code/rodata) or zero-fills (Anonymous).
    /// Hosted tests + the original P2-15a fork path use this.
    ///
    /// For full POSIX fork semantics including Anonymous-page copy,
    /// see [`fork_copy_pages`].
    /// # C: O(N) over VMA count.
    pub fn fork(&self, new_root_pa: u64) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        Ok(Arc::new(Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
        }))
    }

    /// Full POSIX fork per docs/11§7: clone the VMA tree AND copy
    /// every mapped page of every Anonymous VMA into fresh PMM
    /// frames installed in the child PT at `new_root_pa`. KernelBytes-
    /// backed VMAs re-fault in the child against the shared
    /// `&'static [u8]` slice (functionally identical to copy-on-fault
    /// since the data is read-only).
    ///
    /// `new_root_pa` must be an already-allocated PT root with
    /// kernel-half cloned from master per `11§2` invariant 5.
    ///
    /// # SAFETY: source AS is the active CR3 / TTBR0 (so
    /// `M::translate` resolves source PTEs); single-CPU UP;
    /// preempt-off; caller is the `sys_fork` handler.
    /// # C: O(N_vmas + P_anon_pages)
    pub fn fork_copy_pages<M: MmuOps, F: FnMut() -> Option<u64>>(
        &self,
        new_root_pa: u64,
        hhdm_offset: u64,
        mut alloc_frame: F,
    ) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        for vma in src.iter() {
            if !matches!(vma.backing, VmaBacking::Anonymous) { continue; }
            let mut va = vma.start.as_u64();
            let end = vma.end.as_u64();
            while va < end {
                if let Some((src_pa, _)) = M::translate(Va(va)) {
                    let dst_pa = match alloc_frame() {
                        Some(p) => p,
                        None    => return Err(Error::NoMem),
                    };
                    // SAFETY: src_pa came from the active PT walk; HHDM mirror at hhdm + (src_pa&!0xfff) is read-mapped; dst_pa is fresh PMM frame; non-overlapping copy.
                    unsafe {
                        let s = (hhdm_offset + (src_pa.0 & !0xfff)) as *const u8;
                        let d = (hhdm_offset + dst_pa) as *mut u8;
                        core::ptr::copy_nonoverlapping(s, d, PAGE_SIZE_BYTES as usize);
                    }
                    let pte_flags = vma.prot.to_page_flags();
                    // SAFETY: new_root_pa carries kernel-half clone of master per P2-19; va page-aligned in user range; dst_pa fresh; flags carry USER per `11§5`.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(dst_pa), pte_flags, PageSize::P4K);
                    }
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        Ok(Arc::new(Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
        }))
    }

    /// Number of VMAs currently mapped.
    /// # C: O(1)
    pub fn vma_count(&self) -> usize {
        self.vmas.read().len()
    }

    /// Find the VMA covering `va` and return a snapshot. The returned
    /// `Vma` is independent of the tree (so the caller doesn't pin the
    /// read lock).
    /// # C: O(log N)
    pub fn find_vma(&self, va: UserVirtAddr) -> Option<Vma> {
        let g: RwReadGuard<'_, _, _> = self.vmas.read();
        g.find_containing(va).cloned()
    }

    /// Place a new VMA per `11§3` `mmap`.
    ///
    /// - `hint`: candidate placement; with `fixed = true` the request
    ///   is honored exactly (any overlap is cleared first per `11§6`
    ///   `MAP_FIXED`); with `fixed = false` the hint is advisory and a
    ///   first-fit hole search runs if the hint doesn't fit.
    /// - `len`: must be a non-zero multiple of `PAGE_SIZE_BYTES`.
    /// - returns the VMA's start VA on success.
    ///
    /// Returns `Err(Inval)` for misaligned / zero-length requests or
    /// if the hint is `None` while `fixed = true`. `Err(NoMem)` if no
    /// hole large enough exists in the user range.
    /// # C: O(log N) hint path; O(N) hole search fallback
    pub fn mmap(
        &self,
        hint: Option<UserVirtAddr>,
        len: usize,
        prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
        fixed: bool,
    ) -> KResult<UserVirtAddr> {
        validate_len(len)?;
        let len_u64 = len as u64;

        let mut tree = self.vmas.write();

        let start_va = if fixed {
            let h = hint.ok_or(Error::Inval)?;
            validate_aligned(h)?;
            let end = end_of(h, len_u64)?;
            // MAP_FIXED clears overlap before placing per `11§6`.
            tree.remove_range(h, end);
            h
        } else {
            // Try the hint first.
            let from_hint = match hint {
                Some(h) if is_aligned(h) => {
                    end_of(h, len_u64).ok().and_then(|end| {
                        if hole_clear(&tree, h, end) { Some(h) } else { None }
                    })
                }
                _ => None,
            };
            match from_hint {
                Some(h) => h,
                None => find_hole(&tree, len_u64).ok_or(Error::NoMem)?,
            }
        };

        let end_va = end_of(start_va, len_u64)?;
        tree.insert(Vma::new(start_va, end_va, prot, flags, backing))
            .map_err(|_| Error::Inval)?;
        Ok(start_va)
    }

    /// Unmap any VMAs (or VMA fragments) intersecting `[addr, addr+len)`.
    /// Per `11§6`. PT walk + TLB shootdown + page free are out of scope
    /// here; this is the VMA-side bookkeeping only.
    /// # C: O(K + log N)
    pub fn munmap(&self, addr: UserVirtAddr, len: usize) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        let mut tree = self.vmas.write();
        let _ = tree.remove_range(addr, end);
        Ok(())
    }

    /// Change the protection bits over `[addr, addr+len)`. Holes are
    /// rejected with `Inval` per `11§6` ("walk affected VMAs").
    /// # C: O(K log N)
    pub fn mprotect(
        &self,
        addr: UserVirtAddr,
        len: usize,
        prot: VmaProt,
    ) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        let mut tree = self.vmas.write();
        tree.mprotect_range(addr, end, prot)
    }

    /// Audit hook: invariant 1 (non-overlap, `11§2`). Used by tests
    /// and by `debug-vmm` per `11§13`.
    /// # C: O(N)
    pub fn audit(&self) -> KResult<()> {
        self.vmas.read().audit_no_overlap()
    }

    /// Demand-fault handler per `11§5`. v1 covers `NotPresent` of
    /// an `Anonymous` VMA: zero-fill a fresh frame from `alloc_frame`,
    /// install the leaf via `M::map`, return Ok. Other variants land
    /// in subsequent PRs:
    ///
    /// - `NotPresent` of a `File`-backed VMA: needs page cache (`16`).
    /// - `Protection` write on a private writable VMA: COW per `11§5`
    ///   second match arm; needs `PageMeta::refcount` per `11§8`.
    ///
    /// Returns `Ok(())` when the PTE is installed (caller should
    /// retry the faulting instruction). Returns `Err(EFAULT)` when
    /// no VMA covers `va` or the VMA's prot rejects the access —
    /// upstream raises SIGSEGV per `11§5`.
    ///
    /// `hhdm_offset` is the kernel HHDM base for zero-filling the
    /// freshly allocated frame (we write `va + hhdm_offset .. + 4096`
    /// to clear it before exposing to user).
    ///
    /// # SAFETY: `M` is the live per-arch MmuOps with PMM + HHDM
    /// state initialised; `alloc_frame` returns physically-valid
    /// page-aligned PFNs from PMM. Caller's fault context already
    /// disabled IRQs; AS read-lock acquisition here is safe (no
    /// recursion).
    /// # C: O(log N) VMA lookup + O(1) frame zero + O(walk depth) map
    /// # Ctx: fault, IRQ-off
    pub unsafe fn handle_page_fault<M: MmuOps, F: FnMut() -> Option<u64>>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        mut alloc_frame: F,
    ) -> KResult<()> {
        let access = match fault {
            FaultKind::NotPresent { access } => access,
            FaultKind::Protection { .. }     => return Err(Error::NotImplemented),
        };

        // Per spec §5: read VMA tree (concurrent with other faults).
        let g = self.vmas.read();
        let vma = match g.find_containing(va) {
            Some(v) => v,
            None    => return Err(Error::Inval),    // EFAULT upstream
        };
        if !vma.permits(access) {
            return Err(Error::Inval);                // EFAULT upstream
        }

        match vma.backing {
            VmaBacking::Anonymous => {
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                // Zero-fill via HHDM kernel mirror per `11§5` "zero_or_loaded".
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at `hhdm_offset + pa` is mapped writable in
                // the kernel's page tables (Limine-installed); 4096
                // bytes is the page granule.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    core::ptr::write_bytes(dst, 0, PAGE_SIZE_BYTES as usize);
                }
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: va_page is the page-aligned faulting user-half VA per find_containing; pa is a fresh PMM frame; flags carry USER for the leaf U bit per `11§5` to_pte_flags; MmuOps state initialised by the live per-arch impl.
                unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K); }
                Ok(())
            }
            VmaBacking::KernelBytes { data } => {
                // ELF-loader-style demand-fault path per docs/31 §4
                // step 3: copy the file-backed bytes for this page
                // into a fresh PMM frame; bytes past `data.len()`
                // (BSS tail of a PT_LOAD with `p_memsz > p_filesz`)
                // are zero-filled.
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let off = (va_page - vma.start.as_u64()) as usize;
                let page = PAGE_SIZE_BYTES as usize;
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at hhdm_offset+pa is mapped writable; we
                // own the full page exclusively until M::map below
                // makes it user-visible.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    if off >= data.len() {
                        // Entirely BSS (past file-backed extent).
                        core::ptr::write_bytes(dst, 0, page);
                    } else {
                        let avail = (data.len() - off).min(page);
                        // SAFETY: src is a valid &'static [u8] slice covering [off..off+avail]; dst owns `page` bytes; non-overlapping.
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(off), dst, avail,
                        );
                        if avail < page {
                            // SAFETY: dst+avail is within the freshly-allocated frame; tail zero-fills the BSS portion of this page.
                            core::ptr::write_bytes(dst.add(avail), 0, page - avail);
                        }
                    }
                }
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: va_page page-aligned per find_containing; pa is fresh PMM frame; flags carry USER per `11§5`.
                unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K); }
                Ok(())
            }
            VmaBacking::File { .. } | VmaBacking::Special => {
                // File backing requires page cache (`16`); Special
                // requires per-region wiring (vDSO/vvar/hugetlb).
                Err(Error::NotImplemented)
            }
        }
    }
}

#[inline]
fn is_aligned(va: UserVirtAddr) -> bool {
    va.as_u64() % PAGE_SIZE_BYTES == 0
}

#[inline]
fn validate_aligned(va: UserVirtAddr) -> KResult<()> {
    if is_aligned(va) { Ok(()) } else { Err(Error::Inval) }
}

#[inline]
fn validate_len(len: usize) -> KResult<()> {
    if len == 0 || (len as u64) % PAGE_SIZE_BYTES != 0 {
        Err(Error::Inval)
    } else {
        Ok(())
    }
}

#[inline]
fn end_of(start: UserVirtAddr, len: u64) -> KResult<UserVirtAddr> {
    let end = start.as_u64().checked_add(len).ok_or(Error::Inval)?;
    UserVirtAddr::new(end).ok_or(Error::Inval)
}

/// True iff `[start, end)` overlaps no existing VMA.
/// # C: O(N)
fn hole_clear(tree: &VmaTree, start: UserVirtAddr, end: UserVirtAddr) -> bool {
    let s = start.as_u64();
    let e = end.as_u64();
    for v in tree.iter() {
        if v.start.as_u64() >= e { break; }
        if v.end.as_u64()   >  s { return false; }
    }
    true
}

/// First-fit hole search across `[MIN_USER_VA, USER_VA_END)`.
/// # C: O(N)
fn find_hole(tree: &VmaTree, len: u64) -> Option<UserVirtAddr> {
    let mut cursor = MIN_USER_VA;
    for v in tree.iter() {
        let s = v.start.as_u64();
        if s > cursor && s - cursor >= len {
            return UserVirtAddr::new(cursor);
        }
        let e = v.end.as_u64();
        if e > cursor { cursor = e; }
    }
    if USER_VA_END.checked_sub(cursor)? >= len {
        UserVirtAddr::new(cursor)
    } else {
        None
    }
}
