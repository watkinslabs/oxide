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

use hal::{UserVirtAddr, PAGE_SIZE_BYTES, USER_VA_END};
use sync::{AddressSpace as AddressSpaceClass, RwLock, RwReadGuard};

use crate::tree::VmaTree;
use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

/// Lowest user VA this allocator hands out. Page 0 is reserved as the
/// canonical null-pointer trap region per `11§4` (`USER_VA_END` upper
/// bound is in `01§1`).
pub const MIN_USER_VA: u64 = PAGE_SIZE_BYTES;

/// Per-process AS. Public surface mirrors `11§3`. The Page Table side
/// (`11§9`) lands with HAL `MmuOps` in a follow-up P1-N.
pub struct AddressSpace {
    vmas: RwLock<VmaTree, AddressSpaceClass>,
}

impl AddressSpace {
    /// Construct an empty AS, returning a reference-counted handle so
    /// `fork` can share VMA-tree state once COW is wired (`11§7`).
    /// # C: O(1)
    pub fn new() -> KResult<Arc<Self>> {
        Ok(Arc::new(Self { vmas: RwLock::new(VmaTree::new()) }))
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
