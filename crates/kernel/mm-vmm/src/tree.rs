// VMA tree per `11§4`. `BTreeMap<UserVirtAddr, Vma>` keyed by VMA start;
// invariant 1 (non-overlap, `11§2`) enforced on every `insert` and
// preserved by `remove_range` / `mprotect_range`. Adjacent VMAs with
// identical prot/flags/backing-kind and contiguous file offsets are
// merged after insert (`11§4`).
//
// The tree is the inner state of `AddressSpace.vmas`; the outer
// `RwLock<VmaTree>` (`11§9`) lives at the AS layer once `AddressSpace`
// is implemented in a later P1-N.
//
// Page-table walks, TLB shootdowns, and per-page metadata are out of
// scope for this PR; this is the data-structure foundation only.

use core::ops::Bound;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use hal::{UserVirtAddr, USER_VA_END};

use crate::vma::Vma;
use crate::Error;

mod anon_name;

fn raw_end_key(end: u64) -> Option<UserVirtAddr> {
    UserVirtAddr::new(end).or_else(|| if end == USER_VA_END { UserVirtAddr::new(USER_VA_END - 1) } else { None })
}

/// Sorted, non-overlapping set of VMAs covering some subset of user
/// virtual address space. Lookup `O(log N)` (`11§4`); insert worst-case
/// `O(log N)` plus up to two adjacent merges.
pub struct VmaTree {
    map: BTreeMap<UserVirtAddr, Vma>,
}

impl VmaTree {
    /// # C: O(1)
    pub fn new() -> Self { Self { map: BTreeMap::new() } }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.map.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.map.is_empty() }

    /// Find the VMA containing `va`. Returns `None` if `va` falls in a
    /// hole. Lookup is `O(log N)` per `11§4`.
    /// # C: O(log N)
    pub fn find_containing(&self, va: UserVirtAddr) -> Option<&Vma> {
        let (_, v) = self.map.range(..=va).next_back()?;
        if v.contains(va) { Some(v) } else { None }
    }

    /// F158: find a `MAP_GROWSDOWN` VMA whose `start` lies in
    /// `(va, va + max_gap]` — used by the page-fault handler to
    /// auto-extend a stack VMA when access lands just below it.
    /// Linux uses a 64 KiB stack guard gap by default. Returns the
    /// VMA reference for the kernel-side caller to extend.
    /// # C: O(log N)
    pub fn find_growsdown_above(&self, va: UserVirtAddr, max_gap: u64) -> Option<&Vma> {
        // The next-key-up entry from va.
        let (_, v) = self.map.range(va..).next()?;
        if !v.flags.contains(crate::vma::VmaFlags::GROWSDOWN) { return None; }
        let gap = v.start.as_u64().checked_sub(va.as_u64())?;
        if gap > max_gap { return None; }
        Some(v)
    }

    /// F158: extend the `start` of a `MAP_GROWSDOWN` VMA at
    /// `current_start` downward to `new_start` (page-aligned, less
    /// than `current_start`). Returns `Err(Inval)` if the VMA isn't
    /// present, isn't GROWSDOWN, or `new_start` overlaps a lower
    /// neighbor. Used by the stack-grow page-fault path.
    /// # C: O(log N)
    pub fn extend_growsdown_start(
        &mut self,
        current_start: UserVirtAddr,
        new_start: UserVirtAddr,
    ) -> Result<(), Error> {
        if new_start.as_u64() >= current_start.as_u64() { return Err(Error::Inval); }
        if (new_start.as_u64() & (hal::PAGE_SIZE_BYTES - 1)) != 0 { return Err(Error::Inval); }
        // Lower neighbor must not overlap the new range.
        if let Some((_, lower)) = self.map.range(..current_start).next_back() {
            if lower.end.as_u64() > new_start.as_u64() { return Err(Error::Inval); }
        }
        // Take the VMA out, mutate, re-insert under the new key.
        let mut v = self.map.remove(&current_start).ok_or(Error::Inval)?;
        if !v.flags.contains(crate::vma::VmaFlags::GROWSDOWN) {
            // Re-insert unchanged on misuse.
            self.map.insert(current_start, v);
            return Err(Error::Inval);
        }
        v.start = new_start;
        self.map.insert(new_start, v);
        Ok(())
    }

    /// Iterator over VMAs in ascending address order.
    /// # C: O(N) total
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.map.values()
    }

    /// Insert `vma`. Returns `Err(Inval)` if the range is degenerate or
    /// overlaps an existing VMA — caller (`mmap MAP_FIXED`) must call
    /// `remove_range` first to clear the destination per `11§6`.
    ///
    /// After insert, attempts to merge with left and right neighbors
    /// per `11§4` if they are abutting + compatible.
    /// # C: O(log N)
    pub fn insert(&mut self, vma: Vma) -> Result<(), Error> {
        if vma.start.as_u64() >= vma.end.as_u64() {
            return Err(Error::Inval);
        }
        // Floor: largest entry whose key ≤ vma.start. If its end overruns
        // vma.start, we overlap.
        if let Some((_, prev)) = self.map.range(..=vma.start).next_back() {
            if prev.end.as_u64() > vma.start.as_u64() {
                return Err(Error::Inval);
            }
        }
        // Ceil: smallest entry whose key > vma.start (strictly, since
        // the floor branch covered key == vma.start). If its start lies
        // before vma.end, we overlap.
        if let Some((_, next)) = self.map
            .range((Bound::Excluded(vma.start), Bound::Unbounded))
            .next()
        {
            if next.start.as_u64() < vma.end.as_u64() {
                return Err(Error::Inval);
            }
        }
        let key = vma.start;
        self.map.insert(key, vma);
        self.try_merge_left(key);
        // After a left-merge, the entry now lives under the left key;
        // try_merge_right needs to operate from whichever key still
        // exists. Easiest correct path: scan once more from `key` or
        // its predecessor.
        let after_left = if self.map.contains_key(&key) {
            key
        } else {
            // Left-merge consumed `key`; its content now lives under
            // the floor of `key`.
            self.map.range(..key).next_back().map(|(k, _)| *k).unwrap_or(key)
        };
        self.try_merge_right(after_left);
        Ok(())
    }

    fn try_merge_left(&mut self, key: UserVirtAddr) {
        let Some((&lk, _)) = self.map.range(..key).next_back() else { return; };
        let mergeable = {
            let left = &self.map[&lk];
            let cur  = &self.map[&key];
            left.mergeable_with_next(cur)
        };
        if !mergeable { return; }
        let cur = self.map.remove(&key).expect("just-inserted key");
        let left = self.map.get_mut(&lk).expect("left-floor key");
        left.end = cur.end;
        let combined = left.rss.load(core::sync::atomic::Ordering::Relaxed)
            + cur.rss.load(core::sync::atomic::Ordering::Relaxed);
        left.rss.store(combined, core::sync::atomic::Ordering::Relaxed);
    }

    fn try_merge_right(&mut self, key: UserVirtAddr) {
        let Some((&rk, _)) = self.map
            .range((Bound::Excluded(key), Bound::Unbounded))
            .next()
        else { return; };
        let mergeable = {
            let cur   = &self.map[&key];
            let right = &self.map[&rk];
            cur.mergeable_with_next(right)
        };
        if !mergeable { return; }
        let right = self.map.remove(&rk).expect("right-ceil key");
        let cur = self.map.get_mut(&key).expect("merge-target key");
        cur.end = right.end;
        let combined = cur.rss.load(core::sync::atomic::Ordering::Relaxed)
            + right.rss.load(core::sync::atomic::Ordering::Relaxed);
        cur.rss.store(combined, core::sync::atomic::Ordering::Relaxed);
    }

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
            let v = self.map.remove(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.min(v_end);

            // Left-kept fragment.
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in valid range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            // Removed middle.
            let ms = UserVirtAddr::new(s).expect("UVA in valid range");
            let me = UserVirtAddr::new(e).expect("UVA in valid range");
            removed.push(v.clone_subrange(ms, me));
            // Right-kept fragment.
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in valid range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
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
            let v = self.map.remove(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);

            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            mid.prot = new_prot;
            let mid_key = mid.start;
            self.map.insert(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
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
            let v = self.map.remove(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            mid.flags.insert(set);
            mid.flags.remove(clear);
            let mid_key = mid.start;
            self.map.insert(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
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
    /// coverage separately). `Some` sets `UFFD_MISSING`; `None` clears it.
    /// # C: O(K log N)
    pub fn set_uffd_range(
        &mut self,
        start: UserVirtAddr,
        end:   UserVirtAddr,
        ctx:   Option<alloc::sync::Arc<dyn crate::uffd::UffdContext>>,
    ) {
        if start.as_u64() >= end.as_u64() { return; }
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() { keys.push(*k); }
        }
        for k in keys {
            let v = self.map.remove(&k).expect("collected key");
            let v_start = v.start.as_u64();
            let v_end   = v.end.as_u64();
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            match &ctx {
                Some(c) => { mid.uffd = Some(c.clone()); mid.flags.insert(crate::vma::VmaFlags::UFFD_MISSING); }
                None    => { mid.uffd = None;            mid.flags.remove(crate::vma::VmaFlags::UFFD_MISSING); }
            }
            let mid_key = mid.start;
            self.map.insert(mid_key, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
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
            let v = self.map.remove(&k).expect("collected key");
            let (v_start, v_end) = (v.start.as_u64(), v.end.as_u64());
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            mid.flags |= crate::vma::VmaFlags::SEALED;
            self.map.insert(mid.start, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
        }
        Ok(())
    }

    /// True if any VMA overlapping `[start, end)` is `SEALED`. mprotect/
    /// munmap/mremap call this first and return EPERM when true (mseal(2)).
    /// # C: O(N_vma in range)
    pub fn any_sealed(&self, start: UserVirtAddr, end: UserVirtAddr) -> bool {
        self.any_sealed_raw_end(start, end.as_u64())
    }

    /// # C: O(N_vma in range)
    pub fn any_sealed_raw_end(&self, start: UserVirtAddr, end: u64) -> bool {
        let Some(end_key) = raw_end_key(end) else { return false };
        self.map.range(..end_key).any(|(_, v)|
            v.end.as_u64() > start.as_u64()
                && v.flags.contains(crate::vma::VmaFlags::SEALED))
    }
}

impl Default for VmaTree {
    fn default() -> Self { Self::new() }
}
