// Steps every fork strategy performs identically: the parent-side
// copy-on-write decision, the swap-leaf rollback, the per-VMA inheritance
// rules, and publication of the child's reverse-map edges.

use alloc::sync::Arc;

use hal::{MmuOps, Va, PAGE_SIZE_BYTES};

use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};

use super::super::AddressSpace;
/// Whether fork must rewrite the PARENT's leaf read-only so its next write
/// takes a copy-on-write split.
///
/// A leaf that is ALREADY read-only needs no strip — and rewriting it from the
/// VMA protection would destroy per-page state the leaf carries and the VMA
/// does not: a userfaultfd write-protect marker armed on that page. Fork would
/// then silently disarm the monitor's barrier, and the next write would take
/// the copy-on-write path instead of being reported.
/// # C: O(1)
pub(super) fn needs_cow_wrprotect(vma_writable: bool, shared: bool, leaf_writable: bool) -> bool {
    vma_writable && !shared && leaf_writable
}

/// Undo every swap leaf installed in an unpublished child root and return its
/// matching PMM slot reference.  The PTE is cleared before release so no page
/// table can reach a slot after its last reference disappears.
/// # C: O(number of cloned swap PTEs)
pub(super) fn rollback_swap_fork<M: MmuOps, FS: FnMut(hal::pt_walker::SwapEntry)>(
    root_pa: u64, entries: &[(u64, hal::pt_walker::SwapEntry)], release: &mut FS,
) {
    for (va, entry) in entries.iter().rev() {
        // SAFETY: rollback owns the unpublished child root and each tuple was
        // recorded only after the corresponding exact PTE installation.
        let cleared = unsafe { M::clear_swap_at(root_pa, Va(*va), *entry) };
        if cleared { release(*entry); }
    }
}

/// Linux `dup_mmap` drops `VM_LOCKED_MASK` from every inherited VMA: mlock(2)
/// and mlockall(2) state is per-mm and is NOT inherited across fork(2), so a
/// child of an `mlockall(MCL_CURRENT)` parent starts with nothing locked and
/// nothing charged to its RLIMIT_MEMLOCK. Cloning the flags verbatim would let
/// a process multiply its locked footprint by forking.
/// # C: O(1)
pub(super) fn child_vma(vma: &Vma) -> Vma {
    let mut c = vma.clone();
    c.flags.remove(VmaFlags::LOCKED_MASK);
    c
}

/// Publish the child's anon and shared-file reverse-map edges after its Arc
/// exists. Every fork implementation must use this same step. # C: O(N_vmas)
pub(super) fn attach_child_rmaps(child: &Arc<AddressSpace>) {
    let child_weak = Arc::downgrade(child);
    let child_tree = child.vmas.read();
    for vma in child_tree.iter() {
        if let Some(anon) = vma.anon_vma.as_ref() {
            anon.attach(child_weak.clone(), vma.start.as_u64(), vma.end.as_u64());
        }
        if let (Some(rmap), VmaBacking::File { off, .. }) = (&vma.file_rmap, &vma.backing) {
            rmap.attach(
                child_weak.clone(), vma.start.as_u64(), vma.end.as_u64(),
                off / PAGE_SIZE_BYTES, vma.may_prot.contains(VmaProt::WRITE),
            );
        }
    }
}
