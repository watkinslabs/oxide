use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::UserVirtAddr;
use crate::tree::VmaTree;
use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

use super::layout::{end_of, end_of_raw, validate_aligned, validate_len};
use super::limits::STACK_GROW_MAX;
use super::AddressSpace;

/// One VMA subrange whose page-table permissions must follow a successful
/// VMA-side mprotect transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MprotectStep {
    pub start: UserVirtAddr,
    pub len: usize,
    pub prot: VmaProt,
}

/// Linux mprotect may change an earlier VMA before a later VMA fails.
#[derive(Debug, Eq, PartialEq)]
pub struct MprotectOutcome {
    pub steps: Vec<MprotectStep>,
    pub error: Option<Error>,
}

impl AddressSpace {
    /// Configure Linux `mm->def_flags` locking inheritance for new mappings.
    /// # C: O(1)
    pub fn set_mlock_future(&self, enabled: bool, onfault: bool) {
        use core::sync::atomic::Ordering;
        self.mlock_onfault.store(enabled && onfault, Ordering::Release);
        self.mlock_future.store(enabled, Ordering::Release);
    }

    /// Whether a new VMA must be locked and whether it is on-fault only.
    /// # C: O(1)
    pub fn mlock_future_policy(&self) -> (bool, bool) {
        use core::sync::atomic::Ordering;
        let enabled = self.mlock_future.load(Ordering::Acquire);
        (enabled, enabled && self.mlock_onfault.load(Ordering::Acquire))
    }

    /// Snapshot facts owned directly by this address space.
    /// # C: O(1)
    pub fn accounting_snapshot(&self) -> super::VmAccountingSnapshot { self.accounting.snapshot() }

    /// PMM invokes this before clearing a present leaf while the VMA still
    /// exists. Leaf mutation is PMM/HAL-owned; backing classification is VMM-owned.
    /// # C: O(log N)
    pub fn account_pte_remove_at(&self, va: UserVirtAddr) {
        if let Some(vma) = self.find_vma(va) { self.accounting.remove_pte(&vma); }
    }

    /// A leaf installed into a hole by an owner outside the fault path (the
    /// userfaultfd monitor's `UFFDIO_COPY`/`UFFDIO_ZEROPAGE` fill). Callers
    /// that REPLACE a present leaf must not use this: the displaced page was
    /// already counted. # C: O(log N)
    pub fn account_pte_install_at(&self, va: UserVirtAddr) {
        if let Some(vma) = self.find_vma(va) { self.accounting.install_pte(&vma); }
    }

    /// Account one checked present→swap leaf replacement. # C: O(log N)
    pub fn account_present_to_swap_at(&self, va: UserVirtAddr) {
        if let Some(vma) = self.find_vma(va) { self.accounting.remove_pte(&vma); self.accounting.install_swap_pte(); }
    }

    /// Account one checked swap→present leaf replacement. # C: O(log N)
    pub fn account_swap_to_present_at(&self, va: UserVirtAddr) {
        if let Some(vma) = self.find_vma(va) { self.accounting.remove_swap_pte(); self.accounting.install_pte(&vma); }
    }

    /// Account removal of a non-present swap leaf. # C: O(1)
    pub fn account_swap_remove(&self) { self.accounting.remove_swap_pte(); }

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
        let g = self.vmas.read();
        g.find_containing(va).cloned()
    }

    /// Try to extend a `MAP_GROWSDOWN` VMA, Linux `expand_downwards`.
    ///
    /// `max_size` is the largest the WHOLE post-growth VMA may be and
    /// `max_grow` the largest increment this mm may still absorb — both
    /// precomputed by the caller from the faulting task's live `RLIMIT_STACK`
    /// and `RLIMIT_AS` (`acct_stack_growth`'s two rlimit tests). Passing the
    /// caps rather than the limits keeps the `RLIM_INFINITY` sentinel and the
    /// page truncation with the rlimit owner, so this stays mechanism.
    ///
    /// `STACK_GROW_MAX` remains the distance below the VMA a fault may land
    /// and still be read as a stack access (Linux's stack guard gap); it is
    /// NOT a growth cap, which is what `max_size` now is.
    /// # C: O(log N)
    pub fn try_grow_stack(&self, va: UserVirtAddr, max_size: u64, max_grow: u64) -> bool {
        let mut tree = self.vmas.write();
        let (cur_start, cur_end) = match tree.find_growsdown_above(va, STACK_GROW_MAX) {
            Some(v) => (v.start, v.end),
            None    => return false,
        };
        let new_start = UserVirtAddr::new(va.as_u64() & !(hal::PAGE_SIZE_BYTES - 1))
            .expect("va in user range");
        // `acct_stack_growth`: `size` is `vma->vm_end - address`, the whole
        // stack after the growth, and `grow` is the increment charged against
        // the address-space limit.
        if cur_end.as_u64().saturating_sub(new_start.as_u64()) > max_size { return false; }
        if cur_start.as_u64().saturating_sub(new_start.as_u64()) > max_grow { return false; }
        tree.extend_growsdown_start(cur_start, new_start).is_ok()
    }

    /// Snapshot every VMA into a Vec for callers that need a stable
    /// view (e.g. /proc/self/maps). Read-locks the tree briefly.
    /// # C: O(N) clone
    /// madvise fork-behavior core: set/clear VmaFlags over `[start,
    /// start+len)` with boundary splits (Linux madvise_update_vma).
    /// # C: O(K log N)
    pub fn update_flags_range(&self, start: UserVirtAddr, len: usize,
                              set: VmaFlags, clear: VmaFlags) {
        let Some(end) = UserVirtAddr::new(start.as_u64().saturating_add(len as u64)) else { return };
        let locked_bytes = |tree: &VmaTree| tree.iter().filter(|v| {
            v.flags.contains(VmaFlags::LOCKED) && v.end.as_u64() > start.as_u64() && v.start.as_u64() < end.as_u64()
        }).map(|v| v.end.as_u64().min(end.as_u64()) - v.start.as_u64().max(start.as_u64())).sum::<u64>();
        let old_locked = locked_bytes(&self.vmas.read());
        self.vmas.write().update_flags_range(start, end, set, clear);
        let new_locked = locked_bytes(&self.vmas.read());
        self.accounting.replace_locked_range(old_locked, new_locked);
    }

    /// Linux `count_mm_mlocked_page_nr` (`mm/mlock.c`), in BYTES: how much of
    /// `[start, start+len)` is ALREADY `VM_LOCKED`. `do_mlock`'s RLIMIT_MEMLOCK
    /// ladder subtracts this before rejecting, so re-locking a range that is
    /// already locked is not charged against the limit a second time — without
    /// it, an idempotent `mlock()` of the same buffer eventually fails.
    /// # C: O(N)
    pub fn locked_bytes_in_range(&self, start: UserVirtAddr, len: usize) -> u64 {
        let end = start.as_u64().saturating_add(len as u64);
        self.vmas.read().iter().filter(|v| {
            v.flags.contains(VmaFlags::LOCKED) && v.end.as_u64() > start.as_u64() && v.start.as_u64() < end
        }).map(|v| v.end.as_u64().min(end) - v.start.as_u64().max(start.as_u64())).sum()
    }

    /// # C: O(N)
    pub fn snapshot_vmas(&self) -> alloc::vec::Vec<Vma> {
        let g = self.vmas.read();
        g.iter().cloned().collect()
    }

    /// Apply Linux `PR_SET_VMA_ANON_NAME` to `[addr, addr + len)`. `len`
    /// rounds upward to a page exactly as `madvise_set_anon_name` does.
    /// # C: O(K log N)
    pub fn set_anon_vma_name(&self, addr: u64, len: u64,
                             name: Option<Arc<str>>) -> KResult<()> {
        if addr & (hal::PAGE_SIZE_BYTES - 1) != 0 { return Err(Error::Inval); }
        let rounded = len.checked_add(hal::PAGE_SIZE_BYTES - 1)
            .map(|n| n & !(hal::PAGE_SIZE_BYTES - 1)).ok_or(Error::Inval)?;
        if len != 0 && rounded == 0 { return Err(Error::Inval); }
        if rounded == 0 { return Ok(()); }
        let end = addr.checked_add(rounded).ok_or(Error::Inval)?;
        let start = UserVirtAddr::new(addr).ok_or(Error::Inval)?;
        let end = UserVirtAddr::new(end).ok_or(Error::Inval)?;
        self.vmas.write().set_anon_name_range(start, end, name)
    }

    /// Unmap any VMAs (or VMA fragments) intersecting `[addr, addr+len)`.
    /// Per `11§6`. PT walk + TLB shootdown + page free are out of scope
    /// here; this is the VMA-side bookkeeping only.
    /// # C: O(K + log N)
    pub fn munmap(&self, addr: UserVirtAddr, len: usize) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of_raw(addr, len as u64)?;
        let mut tree = self.vmas.write();
        // mseal(2) `vms_gather_munmap_vmas` (`mm/vma.c:1422`): a sealed VMA
        // anywhere in the range refuses the whole unmap, before any split.
        if tree.any_sealed_raw_end(addr, end) { return Err(Error::Perm); }
        // A4-rmap (GAP A4-2): detach the anon_vma chain edges of every
        // VMA the unmap touches (their pre-split ranges), then re-attach
        // the surviving fragments' new ranges after the tree mutation.
        // Linux `unlink_anon_vmas` / `__split_vma` keep the chain in
        // lock-step with the VMA tree; lazy weak-pruning alone leaves
        // stale wide edges (still PTE-checked by the walker, so this is
        // hygiene, not a soundness fix — but it keeps the chain bounded).
        let mut removed = Vec::new();
        self.rmap_resplit(&mut tree, addr.as_u64(), end, |t, s, e| {
            removed = t.remove_range_raw_end(UserVirtAddr::new(s).expect("uva"), e); Ok(())
        })?;
        for vma in &removed { self.accounting.remove_vma(vma); }
        Ok(())
    }

    /// A4-rmap helper: snapshot the anon edges overlapping `[s,e)`,
    /// detach them, run `op` (the tree mutation), then re-attach every
    /// anon VMA fragment still present in the touched super-range. Used
    /// by `munmap` and `mprotect` so VMA splits keep precise rmap edges.
    /// # C: O(K_touched · N_edges)
    fn rmap_resplit<O>(&self, tree: &mut VmaTree, s: u64, e: u64, op: O) -> KResult<()>
    where O: FnOnce(&mut VmaTree, u64, u64) -> KResult<()> {
        // Pass 1: the super-range [lo,hi) spanned by every VMA the op
        // touches (overlaps [s,e)). Splits stay within this span.
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for v in tree.iter() {
            if v.end.as_u64() > s && v.start.as_u64() < e {
                lo = lo.min(v.start.as_u64());
                hi = hi.max(v.end.as_u64());
            }
        }
        if lo > hi { return op(tree, s, e); } // nothing anon to re-key
        // Pass 2: detach EVERY anon edge inside [lo,hi) (not just the
        // [s,e)-overlapping ones) so a fully-contained but untouched VMA
        // is detached and re-attached with the SAME range (net no-op) —
        // never double-attached. Detach matches one (weak,start,end).
        let detach: Vec<(Arc<crate::AnonVma>, u64, u64)> = tree.iter()
            .filter(|v| v.end.as_u64() > lo && v.start.as_u64() < hi)
            .filter_map(|v| v.anon_vma.as_ref()
                .map(|av| (Arc::clone(av), v.start.as_u64(), v.end.as_u64())))
            .collect();
        for (av, vs, ve) in &detach { av.detach(&self.self_weak, *vs, *ve); }
        let file_detach: Vec<(Arc<crate::FileRmap>, u64, u64, u64)> = tree.iter()
            .filter(|v| v.end.as_u64() > lo && v.start.as_u64() < hi)
            .filter_map(|v| match (&v.file_rmap, &v.backing) {
                (Some(rmap), VmaBacking::File { off, .. }) => Some((Arc::clone(rmap), v.start.as_u64(), v.end.as_u64(), off / hal::PAGE_SIZE_BYTES)),
                _ => None,
            })
            .collect();
        for (rmap, vs, ve, idx) in &file_detach { rmap.detach(&self.self_weak, *vs, *ve, *idx); }
        op(tree, s, e)?;
        // Pass 3: re-attach every surviving anon fragment in [lo,hi).
        for v in tree.iter() {
            if v.end.as_u64() > lo && v.start.as_u64() < hi {
                if let Some(av) = v.anon_vma.as_ref() {
                    av.attach(self.self_weak.clone(), v.start.as_u64(), v.end.as_u64());
                }
                if let (Some(rmap), VmaBacking::File { off, .. }) = (v.file_rmap.as_ref(), &v.backing) {
                    rmap.attach(
                        self.self_weak.clone(),
                        v.start.as_u64(),
                        v.end.as_u64(),
                        off / hal::PAGE_SIZE_BYTES,
                        v.may_prot.contains(VmaProt::WRITE),
                    );
                }
            }
        }
        Ok(())
    }

    /// Change the protection bits over `[addr, addr+len)`. Linux commits
    /// complete VMA prefixes and reports `NoMem` if a later page is unmapped.
    /// The kernel-side caller walks every returned successful subrange via
    /// `mprotect_pages` so hardware permissions follow the VMA tree.
    /// # C: O(K log N)
    pub fn mprotect(
        &self,
        addr: UserVirtAddr,
        len: usize,
        prot: VmaProt,
    ) -> KResult<()> {
        let outcome = self.mprotect_user(addr, len, prot, false)?;
        match outcome.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Apply Linux `do_mprotect_pkey`'s per-VMA permission ladder while the
    /// VMA write lock stays held. Earlier steps remain committed if a later
    /// hole, VM_MAY, MDWE, or mseal check fails.
    /// # C: O(K log N)
    pub fn mprotect_user(
        &self,
        addr: UserVirtAddr,
        len: usize,
        requested: VmaProt,
        read_implies_exec: bool,
    ) -> KResult<MprotectOutcome> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        let mut tree = self.vmas.write();
        let count = tree.iter().filter(|vma| {
            vma.end.as_u64() > addr.as_u64() && vma.start.as_u64() < end.as_u64()
        }).count();
        let mut steps = Vec::new();
        steps.try_reserve(count).map_err(|_| Error::NoMem)?;
        let mut cursor = addr.as_u64();
        let mut error = None;
        while cursor < end.as_u64() {
            let Some(vma) = tree.iter().find(|vma| vma.end.as_u64() > cursor) else {
                error = Some(Error::NoMem);
                break;
            };
            if vma.start.as_u64() > cursor {
                error = Some(Error::NoMem);
                break;
            }
            let mut prot = requested;
            if read_implies_exec && requested.contains(VmaProt::READ)
                && vma.may_prot.contains(VmaProt::EXEC)
            {
                prot |= VmaProt::EXEC;
            }
            if !vma.may_prot.contains(prot)
                || self.mdwe_denies_transition(vma.prot, prot)
            {
                error = Some(Error::Access);
                break;
            }
            // Linux checks MDWE before `mprotect_fixup` checks VM_SEALED.
            if vma.flags.contains(VmaFlags::SEALED) {
                error = Some(Error::Perm);
                break;
            }
            let step_end = vma.end.as_u64().min(end.as_u64());
            steps.push(MprotectStep {
                start: UserVirtAddr::new(cursor).expect("validated user range"),
                len: (step_end - cursor) as usize,
                prot,
            });
            cursor = step_end;
        }

        let mut applied = 0;
        while applied < steps.len() {
            let step = steps[applied];
            let step_end = step.start.as_u64() + step.len as u64;
            let result = self.rmap_resplit(
                &mut tree, step.start.as_u64(), step_end,
                |t, s, e| t.mprotect_range(
                    UserVirtAddr::new(s).expect("validated user range"),
                    UserVirtAddr::new(e).expect("validated user range"),
                    step.prot,
                ),
            );
            if let Err(unexpected) = result {
                steps.truncate(applied);
                error = Some(unexpected);
                break;
            }
            applied += 1;
        }
        Ok(MprotectOutcome { steps, error })
    }

    /// True if any VMA in `[addr, addr+len)` is mseal'd. The syscall layer
    /// (sys_mprotect/munmap/mremap) checks this and returns EPERM when true,
    /// per mseal(2). Kernel-internal teardown (exec/exit) bypasses it — only
    /// userspace ops are sealed, matching Linux.
    /// # C: O(K)
    pub fn range_sealed(&self, addr: UserVirtAddr, len: usize) -> bool {
        match end_of_raw(addr, len as u64) {
            Ok(end) => self.vmas.read().any_sealed_raw_end(addr, end),
            Err(_)  => false,
        }
    }

    /// Whether every VMA covering `[addr, addr+len)` permits `prot` (Linux
    /// `VM_MAY*`). Used by `mprotect` to apply `personality(READ_IMPLIES_EXEC)`
    /// only where Linux's per-VMA `VM_MAYEXEC` gate would.
    /// # C: O(K)
    pub fn range_may(&self, addr: UserVirtAddr, len: usize, prot: VmaProt) -> bool {
        match end_of_raw(addr, len as u64) {
            Ok(end) => self.vmas.read().range_may_raw_end(addr, end, prot),
            Err(_)  => false,
        }
    }

    /// mseal(2): seal `[start, end)` so later userspace mprotect/munmap/
    /// mremap/MAP_FIXED/destructive-madvise fail with EPERM. `Err(Inval)` is
    /// reserved for the one condition `do_mseal` reports as ENOMEM: the range
    /// is not fully mapped. Argument validation belongs to `vmm::mseal`, which
    /// the shim has already run — passing an unvalidated range here would
    /// collapse EINVAL into ENOMEM. Idempotent; there is no unseal.
    /// # C: O(K log N)
    pub fn mseal_range(&self, start: UserVirtAddr, end: UserVirtAddr) -> KResult<()> {
        self.vmas.write().seal_range(start, end)
    }

    /// Audit hook: invariant 1 (non-overlap, `11§2`). Used by tests
    /// and by `debug-vmm` per `11§13`.
    /// # C: O(N)
    pub fn audit(&self) -> KResult<()> {
        self.vmas.read().audit_no_overlap()
    }

}
