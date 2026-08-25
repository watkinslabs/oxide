use alloc::vec::Vec;
use hal::UserVirtAddr;
use crate::vma::Vma;
use crate::Error;
use super::{raw_end_key, VmaTree};

impl VmaTree {
    /// Remove every VMA intersecting `[start, end)`. Partial-overlap
    /// VMAs are split at the boundaries; the kept fragments are
    /// reinserted, the removed middles are returned. Mirrors the
    /// `munmap` core per `11§6` (PT walk + TLB shootdown handled at
    /// the AS layer in a later P1-N).
    ///
    /// Returns the removed-middle VMAs in ascending order.
    /// # C: O(K + log N), K = #intersecting VMAs
    pub fn remove_range(
        &mut self,
        start: UserVirtAddr,
        end: UserVirtAddr,
    ) -> Vec<Vma> {
        self.remove_range_raw_end(start, end.as_u64())
    }

    /// # C: O(K + log N), K = #intersecting VMAs
    pub fn remove_range_raw_end(&mut self, start: UserVirtAddr, end: u64) -> Vec<Vma> {
        let mut removed = Vec::new();
        if start.as_u64() >= end { return removed; }
        let Some(end_key) = raw_end_key(end) else { return removed };

        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end_key) {
            if v.end.as_u64() > start.as_u64() {
                keys.push(*k);
            }
        }

        for k in keys {
            let v = self.map_take(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.min(v_end);

            // Left-kept fragment.
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in valid range");
                let left = v.clone_subrange(v.start, lend);
                self.map_put(left.start, left);
            }
            // Removed middle. It never entered the tree, so it never opened;
            // the original's close below is the one that accounts for it.
            let ms = UserVirtAddr::new(s).expect("UVA in valid range");
            let me = UserVirtAddr::new(e).expect("UVA in valid range");
            removed.push(v.clone_subrange(ms, me));
            // Right-kept fragment.
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in valid range");
                let right = v.clone_subrange(rstart, v.end);
                self.map_put(right.start, right);
            }
            crate::vm_ops::vma_closed(&v);
        }
        removed
    }

    /// Apply `new_prot` over `[start, end)`, splitting VMAs at the
    /// boundaries as needed. After update, attempts to merge each
    /// modified VMA with its neighbors. Mirrors `mprotect` core per
    /// `11§6` (PTE demote handled at the AS / HAL layer in a later
    /// P1-N).
    ///
    /// Returns `Err(Inval)` if any byte in `[start, end)` falls in a
    /// hole — partial mprotect is rejected per `11§6` ("walk affected
    /// VMAs"; missing VMA = nothing to walk).
    /// # C: O(K log N)
    pub fn mprotect_range(
        &mut self,
        start: UserVirtAddr,
        end:   UserVirtAddr,
        new_prot: crate::vma::VmaProt,
    ) -> Result<(), Error> {
        self.mprotect_range_with_pkey(start, end, new_prot, None)
    }

    /// `mprotect_range` with an optional replacement VMA protection key.
    /// `None` is legacy mprotect's preserve-key rule. # C: O(K log N)
    pub fn mprotect_range_with_pkey(
        &mut self,
        start: UserVirtAddr,
        end: UserVirtAddr,
        new_prot: crate::vma::VmaProt,
        pkey: Option<u8>,
    ) -> Result<(), Error> {
        if start.as_u64() >= end.as_u64() { return Err(Error::Inval); }

        // First pass: validate full coverage. Walk in-tree from `start`
        // and ensure consecutive VMAs cover [start, end) without holes
        // and allow every requested access bit (`VM_MAY*`).
        let mut cursor = start.as_u64();
        for (_, v) in self.map.range(..end) {
            if v.end.as_u64() <= cursor { continue; }
            if v.start.as_u64() > cursor { return Err(Error::Inval); }
            if !v.may_prot.contains(new_prot) { return Err(Error::Access); }
            cursor = v.end.as_u64();
            if cursor >= end.as_u64() { break; }
        }
        if cursor < end.as_u64() { return Err(Error::Inval); }

        // Second pass: collect overlapping keys, split at boundaries,
        // change prot, re-merge.
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() {
                keys.push(*k);
            }
        }
        for k in keys {
            // A prior fragment can re-merge with this one after both acquire
            // the same protection key. Its old map key was collected before
            // the merge, but the surviving VMA is already complete.
            let Some(v) = self.map_take(&k) else { continue };
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);

            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map_put(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            mid.prot = new_prot;
            if let Some(pkey) = pkey { mid.pkey = pkey; }
            let mid_key = mid.start;
            self.map_put(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map_put(right.start, right);
            }
            // Linux `__split_vma` opens the new VMAs while the original is
            // still live and frees it afterwards; closing first would take a
            // single-attachment SHM_DEST segment to zero mid-split.
            crate::vm_ops::vma_closed(&v);
            // Try merging the modified middle with its neighbors. The
            // boundary fragments retain the old prot, so they merge
            // back together with their original other halves only if
            // we've split a different VMA there earlier — `mergeable`
            // handles the prot check.
            self.try_merge_left(mid_key);
            let after_left = if self.map.contains_key(&mid_key) {
                mid_key
            } else {
                self.map.range(..mid_key).next_back().map(|(k, _)| *k).unwrap_or(mid_key)
            };
            self.try_merge_right(after_left);
        }
        Ok(())
    }

    /// Set/clear VmaFlags over `[start, end)`, splitting at boundaries —
    /// the madvise fork-behavior core (MADV_DONTFORK/DOFORK/WIPEONFORK/
    /// KEEPONFORK, Linux madvise_update_vma). Holes are SKIPPED (Linux
    /// madvise walks present VMAs; ENOMEM-for-hole is the caller's call).
    /// # C: O(K log N)
    pub fn update_flags_range(
        &mut self,
        start: UserVirtAddr,
        end:   UserVirtAddr,
        set:   crate::vma::VmaFlags,
        clear: crate::vma::VmaFlags,
    ) {
        if start.as_u64() >= end.as_u64() { return; }
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() { keys.push(*k); }
        }
        for k in keys {
            let v = self.map_take(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map_put(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            // A secret-memory mapping's lock state is not the caller's to
            // change: its pages have no kernel-visible address, so they can
            // never be reclaimed and the mapping can never be unlocked.
            let (set, clear) = if mid.flags.contains(crate::vma::VmaFlags::SECRETMEM) {
                (set.difference(crate::vma::VmaFlags::LOCKED_MASK),
                 clear.difference(crate::vma::VmaFlags::LOCKED_MASK))
            } else { (set, clear) };
            mid.flags.insert(set);
            mid.flags.remove(clear);
            let mid_key = mid.start;
            self.map_put(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map_put(right.start, right);
            }
            // Linux `__split_vma` opens the new VMAs while the original is
            // still live and frees it afterwards; closing first would take a
            // single-attachment SHM_DEST segment to zero mid-split.
            crate::vm_ops::vma_closed(&v);
            self.try_merge_left(mid_key);
            let after_left = if self.map.contains_key(&mid_key) {
                mid_key
            } else {
                self.map.range(..mid_key).next_back().map(|(k, _)| *k).unwrap_or(mid_key)
            };
            self.try_merge_right(after_left);
        }
    }

    /// userfaultfd(2): set (`Some(ctx)`) or clear (`None`) the uffd
    /// registration over `[start, end)`, splitting at boundaries so the
    /// registration covers exactly the requested range (Linux
    /// `userfaultfd_register` → `vma_modify` split). Holes are skipped
    /// (Linux requires the range be mapped; the syscall layer validates
    /// coverage separately). `Some` installs the context and REPLACES the
    /// mode-flag set with `modes`; `None` drops the context and every mode
    /// flag, so a registration and its modes can never disagree.
    /// # C: O(K log N)
    pub fn set_uffd_range(
        &mut self,
        start: UserVirtAddr,
        end:   UserVirtAddr,
        ctx:   Option<alloc::sync::Arc<dyn crate::uffd::UffdContext>>,
        modes: crate::vma::VmaFlags,
    ) {
        if start.as_u64() >= end.as_u64() { return; }
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() { keys.push(*k); }
        }
        for k in keys {
            let v = self.map_take(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map_put(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            match &ctx {
                Some(c) => {
                    mid.uffd = Some(c.clone());
                    mid.flags.remove(crate::vma::VmaFlags::UFFD_MASK);
                    mid.flags.insert(modes & crate::vma::VmaFlags::UFFD_MASK);
                }
                None => {
                    mid.uffd = None;
                    mid.flags.remove(crate::vma::VmaFlags::UFFD_MASK);
                }
            }
            let mid_key = mid.start;
            self.map_put(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map_put(right.start, right);
            }
            // Linux `__split_vma` opens the new VMAs while the original is
            // still live and frees it afterwards; closing first would take a
            // single-attachment SHM_DEST segment to zero mid-split.
            crate::vm_ops::vma_closed(&v);
            self.try_merge_left(mid_key);
            let after_left = if self.map.contains_key(&mid_key) {
                mid_key
            } else {
                self.map.range(..mid_key).next_back().map(|(k, _)| *k).unwrap_or(mid_key)
            };
            self.try_merge_right(after_left);
        }
    }

    /// Audit hook: verify invariant 1 (non-overlap, `11§2`) over the
    /// entire tree. Used by tests and by the `debug-vmm` cargo feature
    /// (`11§13`). Returns `Err(Inval)` on the first violation.
    /// # C: O(N)
    pub fn audit_no_overlap(&self) -> Result<(), Error> {
        let mut prev_end: u64 = 0;
        for v in self.map.values() {
            if v.start.as_u64() < prev_end { return Err(Error::Inval); }
            if v.end.as_u64() <= v.start.as_u64() { return Err(Error::Inval); }
            prev_end = v.end.as_u64();
        }
        Ok(())
    }

    /// mseal(2): set `SEALED` on every VMA covering `[start, end)`,
    /// splitting at boundaries (same split logic as `mprotect_range`).
    /// Requires full coverage — a hole returns `Err(Inval)` (caller maps
    /// to ENOMEM). Idempotent. Sealed VMAs reject later mprotect/munmap/
    /// mremap (see `any_sealed`).
    /// # C: O(N_vma in range)
    pub fn seal_range(&mut self, start: UserVirtAddr, end: UserVirtAddr) -> Result<(), Error> {
        if start.as_u64() >= end.as_u64() { return Err(Error::Inval); }
        let mut cursor = start.as_u64();
        for (_, v) in self.map.range(..end) {
            if v.end.as_u64() <= cursor { continue; }
            if v.start.as_u64() > cursor { return Err(Error::Inval); }
            cursor = v.end.as_u64();
            if cursor >= end.as_u64() { break; }
        }
        if cursor < end.as_u64() { return Err(Error::Inval); }
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() { keys.push(*k); }
        }
        for k in keys {
            let v = self.map_take(&k).expect("collected key");
            let (v_start, v_end) = (v.start.as_u64(), v.end.as_u64());
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map_put(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            mid.flags |= crate::vma::VmaFlags::SEALED;
            self.map_put(mid.start, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map_put(right.start, right);
            }
            // Linux `__split_vma` opens the new VMAs while the original is
            // still live and frees it afterwards; closing first would take a
            // single-attachment SHM_DEST segment to zero mid-split.
            crate::vm_ops::vma_closed(&v);
        }
        Ok(())
    }

    /// True if any VMA overlapping `[start, end)` is `SEALED`. mprotect/
    /// munmap/mremap call this first and return EPERM when true (mseal(2)).
    /// # C: O(N_vma in range)
    pub fn any_sealed(&self, start: UserVirtAddr, end: UserVirtAddr) -> bool {
        self.any_sealed_raw_end(start, end.as_u64())
    }

    /// Whether every VMA overlapping `[start, end)` permits `prot` (Linux
    /// `VM_MAY*`). `personality(READ_IMPLIES_EXEC)` uses it to decide whether
    /// mprotect may silently add `PROT_EXEC` — Linux gates that per VMA on
    /// `VM_MAYEXEC`, so a range containing a non-executable mapping must not
    /// gain EXEC. An uncovered range answers `false`.
    /// # C: O(N_vma in range)
    pub fn range_may_raw_end(&self, start: UserVirtAddr, end: u64,
        prot: crate::vma::VmaProt) -> bool
    {
        let Some(end_key) = raw_end_key(end) else { return false };
        let mut cursor = start.as_u64();
        for (_, v) in self.map.range(..end_key) {
            if v.end.as_u64() <= cursor { continue; }
            if v.start.as_u64() > cursor { return false; }
            if !v.may_prot.contains(prot) { return false; }
            cursor = v.end.as_u64();
            if cursor >= end { break; }
        }
        cursor >= end
    }

    /// True if `[start, end)` would cut a VMA whose mapped object refuses to
    /// be split (Linux `vm_ops->may_split` returning an error). A range that
    /// covers such a VMA whole, or misses it, is fine — only an interior cut
    /// is refused. munmap/mprotect/mremap call this first and report EINVAL.
    /// # C: O(N_vma in range)
    pub fn refuses_split_raw_end(&self, start: UserVirtAddr, end: u64) -> bool {
        let Some(end_key) = raw_end_key(end) else { return false };
        let s = start.as_u64();
        self.map.range(..end_key).any(|(_, v)| {
            let (vs, ve) = (v.start.as_u64(), v.end.as_u64());
            ve > s && (vs < s || end < ve) && !crate::vm_ops::vma_may_split(v)
        })
    }

    /// # C: O(N_vma in range)
    pub fn refuses_split(&self, start: UserVirtAddr, end: UserVirtAddr) -> bool {
        self.refuses_split_raw_end(start, end.as_u64())
    }

    /// # C: O(N_vma in range)
    pub fn any_sealed_raw_end(&self, start: UserVirtAddr, end: u64) -> bool {
        let Some(end_key) = raw_end_key(end) else { return false };
        self.map.range(..end_key).any(|(_, v)|
            v.end.as_u64() > start.as_u64()
                && v.flags.contains(crate::vma::VmaFlags::SEALED))
    }

}
