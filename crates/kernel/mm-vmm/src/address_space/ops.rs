use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::UserVirtAddr;
use sync::RwReadGuard;

use crate::hole::{find_hole, hole_clear};
use crate::tree::VmaTree;
use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

use super::layout::{end_of, is_aligned, validate_aligned, validate_len};
use super::limits::{MMAP_TOP, STACK_GROW_MAX};
use super::AddressSpace;

impl AddressSpace {
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

    /// Try to extend a `MAP_GROWSDOWN` VMA. D32: cap = 8 MiB
    /// (Linux RLIMIT_STACK default); was 64 KiB which SIGSEGV'd
    /// musl's wide init frames.
    /// # C: O(log N)
    pub fn try_grow_stack(&self, va: UserVirtAddr) -> bool {
        let mut tree = self.vmas.write();
        let cur_start = match tree.find_growsdown_above(va, STACK_GROW_MAX) {
            Some(v) => v.start,
            None    => return false,
        };
        let new_start = UserVirtAddr::new(va.as_u64() & !0xfff)
            .expect("va in user range");
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
        self.vmas.write().update_flags_range(start, end, set, clear);
    }

    /// # C: O(N)
    pub fn snapshot_vmas(&self) -> alloc::vec::Vec<Vma> {
        let g: RwReadGuard<'_, _, _> = self.vmas.read();
        g.iter().cloned().collect()
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
                None => {
                    let top = match self.mmap_base.load(core::sync::atomic::Ordering::Acquire) {
                        0 => MMAP_TOP,
                        v => v,
                    };
                    find_hole(&tree, len_u64, top).ok_or(Error::NoMem)?
                },
            }
        };

        let end_va = end_of(start_va, len_u64)?;
        let is_anon_vma = matches!(backing, VmaBacking::Anonymous);
        tree.insert(Vma::new(start_va, end_va, prot, flags, backing))
            .map_err(|_| Error::Inval)?;
        // A4-rmap (GAP A4-1): attach the owning-AS chain edge for the
        // newly mapped range. Linux `anon_vma_prepare`: the originating
        // mapping MUST be on the chain, or `rmap_walk_anon` enumerates
        // zero targets for a never-forked page (the AS that owns it is
        // invisible). Previously only `fork_cow_pages` attached edges,
        // and only for the child — the parent self-edge was attached
        // nowhere. Bind to the VMA actually in the tree at `start_va`
        // (which may have absorbed `[start_va,end_va)` via an abutting
        // merge), attaching only the newly added sub-range so a merged
        // family never gets an overlapping (double-counting) edge.
        if is_anon_vma {
            if let Some(av) = tree.find_containing(start_va).and_then(|v| v.anon_vma.clone()) {
                av.attach(self.self_weak.clone(), start_va.as_u64(), end_va.as_u64());
            }
        }
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
        // A4-rmap (GAP A4-2): detach the anon_vma chain edges of every
        // VMA the unmap touches (their pre-split ranges), then re-attach
        // the surviving fragments' new ranges after the tree mutation.
        // Linux `unlink_anon_vmas` / `__split_vma` keep the chain in
        // lock-step with the VMA tree; lazy weak-pruning alone leaves
        // stale wide edges (still PTE-checked by the walker, so this is
        // hygiene, not a soundness fix — but it keeps the chain bounded).
        self.rmap_resplit(&mut tree, addr.as_u64(), end.as_u64(), |t, s, e| { let _ = t.remove_range(
            UserVirtAddr::new(s).expect("uva"), UserVirtAddr::new(e).expect("uva")); Ok(()) })?;
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
        op(tree, s, e)?;
        // Pass 3: re-attach every surviving anon fragment in [lo,hi).
        for v in tree.iter() {
            if v.end.as_u64() > lo && v.start.as_u64() < hi {
                if let Some(av) = v.anon_vma.as_ref() {
                    av.attach(self.self_weak.clone(), v.start.as_u64(), v.end.as_u64());
                }
            }
        }
        Ok(())
    }

    /// Change the protection bits over `[addr, addr+len)`. Holes are
    /// rejected with `Inval` per `11§6` ("walk affected VMAs"). VMA
    /// tree is updated; the kernel-side caller (sys_mprotect) walks
    /// affected PT leaves via `mprotect_pages` to flush stale PTEs.
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
        // A4-rmap: mprotect splits VMAs at the range boundaries; keep the
        // anon_vma chain edges in step with the new fragments.
        self.rmap_resplit(&mut tree, addr.as_u64(), end.as_u64(), |t, s, e| {
            t.mprotect_range(
                UserVirtAddr::new(s).expect("uva"),
                UserVirtAddr::new(e).expect("uva"), prot)
        })
    }

    /// True if any VMA in `[addr, addr+len)` is mseal'd. The syscall layer
    /// (sys_mprotect/munmap/mremap) checks this and returns EPERM when true,
    /// per mseal(2). Kernel-internal teardown (exec/exit) bypasses it — only
    /// userspace ops are sealed, matching Linux.
    /// # C: O(K)
    pub fn range_sealed(&self, addr: UserVirtAddr, len: usize) -> bool {
        match end_of(addr, len as u64) {
            Ok(end) => self.vmas.read().any_sealed(addr, end),
            Err(_)  => false,
        }
    }

    /// mseal(2): seal `[addr, addr+len)` so later userspace mprotect/munmap/
    /// mremap fail with EPERM. Full coverage required (hole → Inval, which the
    /// shim maps to ENOMEM). Idempotent.
    /// # C: O(K log N)
    pub fn mseal(&self, addr: UserVirtAddr, len: usize) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        self.vmas.write().seal_range(addr, end)
    }

    /// Audit hook: invariant 1 (non-overlap, `11§2`). Used by tests
    /// and by `debug-vmm` per `11§13`.
    /// # C: O(N)
    pub fn audit(&self) -> KResult<()> {
        self.vmas.read().audit_no_overlap()
    }

}
