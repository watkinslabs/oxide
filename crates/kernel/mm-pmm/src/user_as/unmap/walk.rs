use super::*;
use hal::pt_walker::PtWalker;

pub(super) enum NonpresentKind { Swap, Marker, Migration }

/// Classify one non-present leaf after one page-table walk. # C: O(4)
pub(super) fn current_nonpresent_kind(va: u64) -> Option<NonpresentKind> {
    let raw = unsafe {
        #[cfg(target_arch = "x86_64")]
        { hal::pt_walker::raw_leaf_4k::<hal_x86_64::vmm::PtWalkerX86>(va, hhdm_offset()) }
        #[cfg(target_arch = "aarch64")]
        { hal::pt_walker::raw_leaf_4k::<hal_aarch64::vmm::PtWalkerArm>(va, hhdm_offset()) }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = va; None }
    }?;
    #[cfg(target_arch = "x86_64")]
    let (swap, marker, migration) = (
        hal_x86_64::vmm::PtWalkerX86::unpack_swap_entry(raw).is_some(),
        hal_x86_64::vmm::PtWalkerX86::unpack_pte_marker(raw).is_some(),
        hal_x86_64::vmm::PtWalkerX86::unpack_migration_entry(raw).is_some());
    #[cfg(target_arch = "aarch64")]
    let (swap, marker, migration) = (
        hal_aarch64::vmm::PtWalkerArm::unpack_swap_entry(raw).is_some(),
        hal_aarch64::vmm::PtWalkerArm::unpack_pte_marker(raw).is_some(),
        hal_aarch64::vmm::PtWalkerArm::unpack_migration_entry(raw).is_some());
    if swap { Some(NonpresentKind::Swap) }
    else if marker { Some(NonpresentKind::Marker) }
    else if migration { Some(NonpresentKind::Migration) }
    else { None }
}

/// Tear down the present leaf at `va` and return its physical address and
/// installed granule. Combining lookup and clear avoids the old two-walk
/// sequence (`translate_sized` followed by `unmap`) and avoids a second local
/// TLB invalidation: `unmap_at_va` performs the clear and its architecture's
/// local flush together, matching Linux's single zap walk under `mmu_gather`.
///
/// # SAFETY: the caller owns the active address space's teardown and `va` is
/// not concurrently modified.
/// # C: O(walk depth)
pub(super) unsafe fn unmap_leaf(va: u64) -> Option<(u64, hal::PageSize)> {
    let hhdm = hhdm_offset();
    let (raw, level) = unsafe {
        #[cfg(target_arch = "x86_64")]
        { hal::pt_walker::unmap_at_va::<hal_x86_64::vmm::PtWalkerX86>(va, hhdm)? }
        #[cfg(target_arch = "aarch64")]
        { hal::pt_walker::unmap_at_va::<hal_aarch64::vmm::PtWalkerArm>(va, hhdm)? }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = (va, hhdm); return None; }
    };
    let size = match level {
        1 => hal::PageSize::P1G,
        2 => hal::PageSize::P2M,
        3 => hal::PageSize::P4K,
        _ => return None,
    };
    #[cfg(target_arch = "x86_64")]
    let pa = raw & hal_x86_64::vmm::PtWalkerX86::PHYS_MASK;
    #[cfg(target_arch = "aarch64")]
    let pa = raw & hal_aarch64::vmm::PtWalkerArm::PHYS_MASK;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let pa = raw;
    Some((pa + (va & (size.bytes() - 1)), size))
}

/// Release one mapping's reference to the frame a just-cleared leaf named.
///
/// A block leaf names a hugetlb page, whose home is the huge-page pool and not
/// the buddy allocator: dropping it through the ordinary free-on-zero path
/// would return pool memory to the buddy and silently shrink the pool an
/// operator sized. Base leaves keep the ordinary rmap-aware path.
///
/// The huge release is the same one for a shared page and for a private COW
/// copy, and it has to be: the zap walk sees a leaf, not an owner. It works
/// because the two carry different reference counts — a file's page is held by
/// the file as well as by each mapping, so dropping a mapping never takes it to
/// zero, while a private copy is held only by the mapping that owns it and goes
/// straight back to the pool.
/// # SAFETY: the leaf was cleared and invalidated on every CPU before this
/// call, so no translation can still reach the frame.
/// # C: O(1) amortised for a base page; O(log nr_hugepages) for a huge page.
pub(super) unsafe fn release_leaf_frame(pa: u64, size: hal::PageSize) {
    let Some(huge) = crate::hugetlb::HugePageSize::from_leaf(size) else {
        // SAFETY: per this function's contract; the ordinary path releases to
        // the buddy only when no address space maps the frame any more.
        unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa & PAGE_ALIGN_MASK); }
        return;
    };
    crate::hugetlb::huge_frame_dec_and_maybe_release(huge, pa & !(size.bytes() - 1));
}

/// Whether this range would cut a huge mapping off a huge-page boundary.
/// # C: O(N_vmas in range)
pub(super) fn huge_split_refused(range: MunmapRange) -> bool {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; read-only mm slot query.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            return mm.huge_split_refused(range.start, range.end);
        }
    }
    with(|as_| as_.huge_split_refused(range.start, range.end)).unwrap_or(false)
}

/// # C: O(log N_vmas)
pub(super) fn range_sealed(range: MunmapRange) -> bool {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; read-only mm slot query.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            return mm.range_sealed(range.start, range.len_aligned);
        }
    }
    with(|as_| as_.range_sealed(range.start, range.len_aligned)).unwrap_or(false)
}

/// Zap one current-address-space swap PTE under the same PTE lock that
/// serializes swap-in and pageout.  Returning the entry transfers its one PTE
/// reference to the caller, which must immediately release the swap slot.
/// # C: O(walk depth)
pub(super) fn clear_swap_entry(as_: &AddressSpace, va: u64) -> Option<hal::pt_walker::SwapEntry> {
    let _pt = as_.lock_page_table();
    // SAFETY: the address-space PTE lock is held and HHDM covers this live root.
    let cleared = unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let entry = hal::pt_walker::swap_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, hhdm_offset())?;
            hal::pt_walker::clear_swap_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
        }
        #[cfg(target_arch = "aarch64")]
        {
            let entry = hal::pt_walker::swap_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, hhdm_offset())?;
            hal::pt_walker::clear_swap_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = (as_, va); None }
    };
    if cleared.is_some() { as_.account_swap_remove(); }
    cleared
}

/// Retire one present leaf (or migration marker, which this kernel accounts as
/// still-resident until it resolves) from the resident-set counters of the
/// address space this zap loop walks. Linux does the same inside
/// `zap_pte_range` via `add_mm_rss_vec`; without it `anon_pte_mappings` and
/// `file_pte_mappings` only ever grow, so `VmRSS`, `statm` and `ru_maxrss`
/// drift upward without bound for any process that unmaps anything.
/// Resolution mirrors `clear_current_swap_entry`: the running task's mm is
/// authoritative, and the boot address space is the pre-installation fallback.
/// # C: O(log N_vmas)
pub(super) fn account_present_removed(va: u64) {
    let Some(uva) = hal::UserVirtAddr::new(va) else { return; };
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context is the current task's sole address-space writer.
        if let Some(mm) = unsafe { cur.mm_ref() } { mm.account_pte_remove_at(uva); return; }
    }
    let _ = with(|as_| as_.account_pte_remove_at(uva));
}

/// Resolve the active task's authoritative address space, falling back only
/// before task-mm installation to the boot address space used by syscall glue.
/// # C: O(walk depth)
pub(super) fn clear_current_swap_entry(va: u64) -> Option<hal::pt_walker::SwapEntry> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context is the current task's sole address-space writer.
        if let Some(mm) = unsafe { cur.mm_ref() } { return clear_swap_entry(mm, va); }
    }
    with(|as_| clear_swap_entry(as_, va)).flatten()
}

/// Remove one exact migration marker.  Unlike swap, this transfers no slot
/// reference: it only drops this PTE's participation in the in-flight
/// transaction so commit/rollback can retire its token safely.
pub(super) fn clear_migration_entry(as_: &AddressSpace, va: u64) -> Option<hal::pt_walker::MigrationEntry> {
    let _pt = as_.lock_page_table();
    // SAFETY: PTE lock is held and this AS root is live under HHDM.
    #[cfg(target_arch = "x86_64")]
    let cleared = unsafe {
        let entry = hal::pt_walker::migration_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, hhdm_offset())?;
        hal::pt_walker::clear_migration_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
    };
    // SAFETY: same held PTE lock, live borrowed root and HHDM coverage as the
    // x86_64 arm above; only the walker type differs.
    #[cfg(target_arch = "aarch64")]
    let cleared = unsafe {
        let entry = hal::pt_walker::migration_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, hhdm_offset())?;
        hal::pt_walker::clear_migration_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let cleared = { let _ = (as_, va); None };
    cleared
}

pub(super) fn clear_current_migration_entry(va: u64) -> Option<hal::pt_walker::MigrationEntry> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context owns this task's AS mutation.
        if let Some(mm) = unsafe { cur.mm_ref() } { return clear_migration_entry(mm, va); }
    }
    with(|as_| clear_migration_entry(as_, va)).flatten()
}

/// Remove a userfaultfd marker of ANY kind. Zapping a range removes the memory
/// the marker described, so leaving it behind would make the NEXT mapping of
/// that address raise a memory error, or report a write-protect fault to a
/// monitor, for a mapping that no longer exists — a `MADV_DONTNEED`ed range
/// must refault as fresh zeroes. Nothing is freed: a marker names no frame and
/// no swap slot.
/// # C: O(walk depth)
pub(super) fn clear_pte_marker(as_: &AddressSpace, va: u64) -> bool {
    let _pt = as_.lock_page_table();
    // SAFETY: the address-space PTE lock is held and HHDM covers this live root; a marker leaf is non-present, so replacing it with an absent leaf unmaps nothing and drops no reference.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { clear_marker_at::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va) }
        #[cfg(target_arch = "aarch64")]
        { clear_marker_at::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va) }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = (as_, va); false }
    }
}

/// # SAFETY: caller holds the address space's page-table lock and owns `root`.
/// # C: O(walk depth)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn clear_marker_at<W: hal::pt_walker::PtWalker>(root: u64, va: u64) -> bool {
    // SAFETY: per fn contract — the read and the exchange both run under the caller's page-table lock, and the exchange writes only when the leaf still holds exactly the marker it read.
    unsafe {
        let Some(raw) = hal::pt_walker::read_leaf_4k_at_root::<W>(root, va, hhdm_offset())
            else { return false };
        if W::unpack_pte_marker(raw).is_none() { return false; }
        hal::pt_walker::swap_leaf_if_4k_at_root::<W>(root, va, raw, 0, hhdm_offset())
    }
}

/// Run `f` against the address space these zaps operate on: the running task's
/// when there is one, otherwise the global boot one — the same choice the rest
/// of this module makes for its VMA bookkeeping.
/// # C: O(1) + f
fn with_zap_target<R>(f: impl FnOnce(&AddressSpace) -> R) -> Option<R> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; preempt-off; single-mutator mm slot per 13§5; the closure only reads the VMA tree.
        if let Some(mm) = unsafe { cur.mm_ref() } { return Some(f(mm)); }
    }
    with(f)
}

/// Charge an impending zap of `[start, end)` against every monitor tracking
/// `kind`, so no resolve can land in the range while it is being torn down.
/// # C: O(N_vmas)
pub(super) fn zap_watchers(start: u64, end: u64, kind: vmm::UffdEventKind)
    -> alloc::vec::Vec<alloc::sync::Arc<dyn vmm::UffdContext>> {
    with_zap_target(|as_| as_.uffd_change_begin(start, end, kind)).unwrap_or_default()
}

/// # C: O(walk depth)
pub(super) fn clear_current_pte_marker(va: u64) -> bool {
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context owns this task's AS mutation.
        if let Some(mm) = unsafe { cur.mm_ref() } { return clear_pte_marker(mm, va); }
    }
    with(|as_| clear_pte_marker(as_, va)).unwrap_or(false)
}
