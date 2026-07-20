use alloc::sync::Arc;

use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES};

use crate::vma::{FaultAccess, FaultKind};
use crate::{Error, KResult};

use super::AddressSpace;

mod fill;
mod device;
mod write;

impl AddressSpace {
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
    /// Back-compat wrapper: handle_page_fault without per-page
    /// refcount awareness. Always copies on Protection-write
    /// (correct for refcount==1 owner-only writes; suboptimal for
    /// COW-shared frames where a refcount-aware handler could
    /// short-circuit the copy when count==1). Real COW-aware path:
    /// `handle_page_fault_cow`.
    /// # SAFETY: same as `handle_page_fault_cow`.
    /// # C: same as `handle_page_fault_cow`.
    pub unsafe fn handle_page_fault<M: MmuOps, F: FnMut() -> Option<u64>>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        alloc_frame: F,
    ) -> KResult<()> {
        // SAFETY: forward to COW path with no-op refcount/dec hooks.
        unsafe {
            self.handle_page_fault_cow::<M, _, _, _>(
                va, fault, hhdm_offset, alloc_frame,
                |_pa: u64| 2u32, // pretend always shared so the
                                  // copy path runs (matches old
                                  // behaviour: copy on Protection-write).
                |_pa: u64| {},
            )
        }
    }

    /// COW-aware page-fault handler. Adds two callbacks to the
    /// classic resolver:
    ///   - `frame_refcount(pa) -> u32`: per-PA struct-page refcount.
    ///     If 1, the faulting AS is the sole owner — flip the W bit
    ///     in place (no copy).
    ///   - `dec_ref(pa)`: drop one reference (used when COW splits a
    ///     shared frame; the faulting AS now points at a fresh frame
    ///     and no longer references the shared one).
    /// # SAFETY: same as `handle_page_fault`.
    /// # C: O(log N_vmas) + O(1) on Anonymous; +O(page) on COW-copy.
    pub unsafe fn handle_page_fault_cow<M, A, RC, DR>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        alloc_frame: A,
        frame_refcount: RC,
        dec_ref: DR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        RC: FnMut(u64) -> u32,
        DR: FnMut(u64),
    {
        // Forward to the rmap-aware variant with no-op rmap hooks.
        // Hosted tests + boot-only callers that don't need page->mapping
        // bookkeeping go through this thin wrapper; the kernel's
        // user-fault dispatcher uses `handle_page_fault_cow_rmap`.
        // SAFETY: forwarded preconditions per `handle_page_fault_cow_rmap`.
        unsafe {
            self.handle_page_fault_cow_rmap::<M, _, _, _, _, _, _, _, _>(
                va, fault, hhdm_offset,
                alloc_frame, frame_refcount, dec_ref,
                |_pa, _av, _idx| {},
                |_pa| {},
                |_pa| false, // no PageMeta exclusivity proof → copy-always
                || Ok(()),
                || {},
            )
        }
    }

    /// rmap-aware COW + demand-page handler. Identical to
    /// `handle_page_fault_cow` but invokes `set_rmap` after every
    /// successful frame install so the kernel side can record the
    /// new (page → AnonVma, page_index) edge per Linux
    /// `page_add_anon_rmap`. Hosted tests pin no-op `set_rmap`.
    /// # SAFETY: per `handle_page_fault_cow`.
    /// # C: O(N_vmas) on lookup + O(walk) on install.
    pub unsafe fn handle_page_fault_cow_rmap<M, A, RC, DR, SR, IR, XR, CA, UA>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        mut alloc_frame: A,
        mut frame_refcount: RC,
        mut dec_ref: DR,
        mut set_rmap: SR,
        mut inc_ref: IR,
        mut reuse_ok: XR,
        mut charge_anon: CA,
        mut uncharge_anon: UA,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        RC: FnMut(u64) -> u32,
        DR: FnMut(u64),
        SR: FnMut(u64, &Arc<crate::AnonVma>, u32),
        IR: FnMut(u64),
        // A3: `reuse_ok(pa)` returns true iff `pa` is an exclusively-owned
        // anonymous frame (Linux `PageAnonExclusive` + mapcount==1) — the
        // sole-mapper proof that lets a write fault reuse the frame in
        // place (`wp_page_reuse`) instead of COW-copying. The kernel
        // adapter implements it as `is_anon && is_anon_exclusive &&
        // mapcount==1` over `PageMeta`; hosted no-op callers pass
        // `|_| false` (copy-always, the previous behaviour).
        XR: FnMut(u64) -> bool,
        // `charge_anon` is a provisional memcg admission. It runs before an
        // anonymous first-touch or a private COW-copy receives a frame; the
        // matching `uncharge_anon` must undo that admission if allocation
        // fails before a new page is installed. This leaves the VMM policy
        // free while making the PMM/cgroup ownership boundary explicit.
        CA: FnMut() -> KResult<()>,
        UA: FnMut(),
    {
        self.accounting.fault();
        // Linux `handle_pte_fault`: when the PTE is ABSENT the fault is a
        // FIRST TOUCH (`do_pte_missing` → do_anonymous_page / do_fault) no
        // matter what the hardware error code claims — a stale TLB entry or
        // a zap race can deliver a protection-write fault for a leaf that is
        // gone. Normalize such faults to NotPresent BEFORE the Protection
        // branch below: its cur==None fallback allocated a ZERO page even for
        // File/KernelBytes backings, installing zeros over file content
        // (Linux do_cow_fault READS the backing page first). That zero page
        // landed on the EOF-straddling .data/.dynamic tail of freshly-mapped
        // shared libraries — ld.so then silently skipped DT_NEEDED deps
        // (dl-version.c `needed != NULL` assert), hit bogus undefined-symbol
        // errors, or wedged on a zeroed lock word: the random-victim exit-127
        // / futex-wedge boot corruption.
        let fault = match fault {
            FaultKind::Protection { access } => {
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                // SAFETY: va_page is in user-half; M::translate reads the
                // active PT for the running task's CR3 / TTBR0.
                if unsafe { M::translate(Va(va_page)) }.is_none() {
                    FaultKind::NotPresent { access }
                } else {
                    FaultKind::Protection { access }
                }
            }
            f => f,
        };
        // Protection write to a writable VMA — CoW-style
        // upgrade. Three causes hit this:
        //   (a) eager-copy at fork installed the leaf with the
        //       VMA's prot, but the prot translation cleared
        //       the W bit due to a to_page_flags quirk —
        //       resolved by re-installing fresh with the same
        //       flags.
        //   (b) shared KernelBytes leaf (loader installed the
        //       RO master Box for a PT_LOAD with W flag) — the
        //       child needs its own writable copy of the page.
        //   (c) future real CoW — a child wrote to a page the
        //       parent shared at fork time. Same handler works:
        //       allocate fresh frame, copy current bytes, install
        //       writable PTE.
        // VMA-prot mismatch (write to RO VMA) → Err(Inval) →
        // upstream EFAULT or SIGSEGV per fault context.
        if let FaultKind::Protection { access: FaultAccess::Write } = fault {
            // SAFETY: same fault-context and callback contracts as this dispatcher.
            return unsafe {
                self.handle_write_protection::<M, _, _, _, _, _, _, _>(
                    va, hhdm_offset, &mut alloc_frame, &mut frame_refcount,
                    &mut dec_ref, &mut set_rmap, &mut reuse_ok,
                    &mut charge_anon, &mut uncharge_anon,
                )
            };
        }
        let access = match fault {
            FaultKind::NotPresent { access } => access,
            // Linux `spurious_fault`: only Read/Exec protection faults reach
            // here (Write took the branch above; absent leaves were
            // normalized to NotPresent). The leaf is PRESENT, so if the VMA
            // permits the access this fault came from a stale TLB entry or
            // stale leaf permissions — re-install the leaf from the VMA prot
            // (preserving a COW W-strip) and retry, never kill. A genuine
            // VMA-forbidden access stays EFAULT/SIGSEGV.
            FaultKind::Protection { access } => {
                let g = self.vmas.read();
                let vma = g.find_containing(va).ok_or(Error::Inval)?;
                if !vma.permits(access) { return Err(Error::Inval); }
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                // SAFETY: privileged PT read of the running task's active root.
                if let Some((pa, old_fl)) = unsafe { M::translate(Va(va_page)) } {
                    let mut f = vma.prot.to_page_flags();
                    if f.contains(hal::PageFlags::WRITE) && !old_fl.contains(hal::PageFlags::WRITE) {
                        f.remove(hal::PageFlags::WRITE); // keep COW W-strip
                    }
                    #[cfg(feature = "debug-atexit")]
                    if let crate::vma::VmaBacking::File { backing, off } = &vma.backing {
                        let foff = off.wrapping_add(va_page - vma.start.as_u64());
                        crate::tailwatch::log_install(b"spurious", backing.ino(), foff, va_page, pa.0 & !(PAGE_SIZE_BYTES - 1), 0);
                    }
                    // SAFETY: same-PA permission refresh; M::map self-flushes.
                    unsafe { M::map(Va(va_page), Pa(pa.0 & !(PAGE_SIZE_BYTES - 1)), f, PageSize::P4K); }
                } else {
                    // Raced away between normalization and here — flush and
                    // let the refault take the NotPresent path.
                    // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
                    unsafe { M::flush_va(Va(va_page)); }
                }
                return Ok(());
            }
        };

        // SAFETY: dispatches the NotPresent backing fill under the same callback contracts.
        unsafe {
            self.handle_not_present::<M, _, _, _, _, _, _>(
                va, access, hhdm_offset, &mut alloc_frame,
                &mut dec_ref, &mut set_rmap, &mut inc_ref,
                &mut charge_anon, &mut uncharge_anon,
            )
        }
    }
}
