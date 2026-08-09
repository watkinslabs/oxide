// Kernel linear-map page-attribute control.
//
// The linear map reaches every page of RAM through one enormous set of large
// leaves. That is what makes ordinary kernel access to a page free, and it is
// also why a page that must NOT be reachable from the kernel cannot simply be
// allocated: it has to be taken out of the linear map, which means the large
// leaf covering it must first become small leaves (`hal::pt_walker` split), and
// then the one leaf naming it must stop translating.
//
// Whether that is possible at all is `can_set_direct_map`, and each
// architecture answers it from the mechanisms it actually has. One
// re-granularises a live kernel mapping on demand and is therefore always
// capable. The other cannot promise that on every implementation, so its boot
// policy builds the RAM half of the map at page granularity instead — there is
// then no granularity to change, and the capability holds regardless of what
// the implementation advertises. A caller that finds the answer `false` must
// not pretend the page is unreachable.
//
// Removal and restoration are published separately from their TLB flush,
// because a caller that is about to hand the page somewhere else batches one
// flush after the whole sequence rather than paying a cross-CPU round trip per
// page. Nothing here flushes remote CPUs on its own; `flush_kernel_range` does.

use syscall::errno::Errno;

#[cfg(target_arch = "x86_64")]
use hal_x86_64::vmm::PtWalkerX86 as ArchWalker;
#[cfg(target_arch = "aarch64")]
use hal_aarch64::vmm::PtWalkerArm as ArchWalker;

use hal::pt_walker::PtWalker;

/// Serializes every linear-map granularity or attribute change. One global
/// lock, because the map is one global structure: two CPUs splitting the same
/// large leaf would otherwise each publish a table and one would leak while the
/// other's children were never seen.
static CPA_LOCK: sync::Spinlock<(), sync::PageTable> = sync::Spinlock::new(());

/// Whether single pages can be removed from and restored to the kernel's
/// linear map on this machine.
/// # C: O(1)
pub fn can_set_direct_map() -> bool { ArchWalker::can_split_kernel_leaf() }

/// Kernel linear-map address of `pa`.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn linear_va(pa: u64) -> u64 { crate::user_as::hhdm_offset().wrapping_add(pa) }

/// Stop the linear map translating the page at `pa`, without flushing.
/// `Ok(())` when the architecture cannot do this at all, mirroring the
/// reference's silent success there: the caller's page is then ordinary RAM and
/// the capability query is what decides whether that is acceptable.
/// # C: O(walk depth), plus one table fill per level that had to be split
/// # Lk: CPA_LOCK acquired
#[cfg(target_os = "oxide-kernel")]
pub fn set_direct_map_invalid_noflush(pa: u64) -> Result<(), Errno> { set_linear_present(pa, false) }

/// Restore the linear-map translation for `pa`, without flushing.
/// # C: O(walk depth)
/// # Lk: CPA_LOCK acquired
#[cfg(target_os = "oxide-kernel")]
pub fn set_direct_map_default_noflush(pa: u64) -> Result<(), Errno> { set_linear_present(pa, true) }

/// Whether the linear map currently translates `pa`.
/// # C: O(walk depth)
#[cfg(target_os = "oxide-kernel")]
pub fn kernel_page_present(pa: u64) -> bool {
    if !can_set_direct_map() { return true; }
    let va = linear_va(pa);
    let hhdm = crate::user_as::hhdm_offset();
    // SAFETY: privileged read of the active kernel translation base.
    let root = unsafe { ArchWalker::read_pt_base(va) };
    let _g = CPA_LOCK.lock();
    // SAFETY: read-only walk of the live kernel tables through the HHDM, under
    // the lock that serializes every mutation of them.
    unsafe { hal::pt_walker::leaf_present_at_root::<ArchWalker>(root, va, hhdm) }
}

/// Split down to a single-page leaf for `pa` and set its translation state.
/// # C: O(walk depth)
/// # Lk: CPA_LOCK acquired
#[cfg(target_os = "oxide-kernel")]
fn set_linear_present(pa: u64, present: bool) -> Result<(), Errno> {
    if !can_set_direct_map() { return Ok(()); }
    let va = linear_va(pa);
    let hhdm = crate::user_as::hhdm_offset();
    if hhdm == 0 { return Err(Errno::Einval); }
    // SAFETY: privileged read of the active kernel translation base; the
    // returned root is the tree every CPU is walking for kernel addresses.
    let root = unsafe { ArchWalker::read_pt_base(va) };
    let _g = CPA_LOCK.lock();
    // SAFETY: the lock makes the kernel tables exclusively ours for this walk;
    // HHDM covers page-table memory; the allocator yields fresh kernel frames.
    let split = unsafe {
        hal::pt_walker::split_kernel_leaf_at_root::<ArchWalker, _>(
            root, va, hhdm, || super::alloc_page_table_frame(0))
    };
    match split {
        Ok(()) => {}
        Err(hal::pt_walker::WalkErr::AllocFailed) => return Err(Errno::Enomem),
        Err(_) => return Err(Errno::Einval),
    }
    // The split guarantees a single-page leaf exists, so a refusal here means
    // the address is not in the linear map at all.
    // SAFETY: same lock, same live root; the rewrite preserves the leaf's
    // output address and attributes.
    if !unsafe { hal::pt_walker::set_leaf_present_at_root::<ArchWalker>(root, va, present, hhdm) } {
        return Err(Errno::Einval);
    }
    Ok(())
}

// --- execute permission ----------------------------------------------------
//
// A kernel that copies code into the linear map and then CALLS it is relying on
// that mapping permitting instruction fetch. Until this existed nothing here
// asserted it: the boot tables happen to build the direct map out of large
// leaves with no no-execute control set, so the call worked by inheritance.
// That is not a property anyone chose, nothing would notice it changing, and
// the reference does not depend on it — it narrows the page it is about to run
// from to read-only-and-executable, explicitly, before jumping.
//
// Read-only AND executable, not merely executable: the code is complete by the
// time this runs, and a page that is about to be entered has no reason to stay
// writable. Narrowing both in one rewrite is also the only way to avoid a
// window in which the page is simultaneously writable and executable.

/// Whether a raw leaf permits instruction fetch in kernel mode, decoded by the
/// architecture that packed it.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn leaf_is_kernel_exec(entry: u64) -> bool { hal_x86_64::vmm::leaf_is_kernel_exec(entry) }
/// See the x86_64 arm.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn leaf_is_kernel_exec(entry: u64) -> bool { hal_aarch64::vmm::leaf_is_kernel_exec(entry) }

/// `set_memory_rox`: make `pages` pages at `va` read-only and executable in the
/// kernel's own map, and flush the change everywhere.
///
/// `va` is a kernel address, not a physical one — the caller names the mapping
/// it is going to run through, which on the linear map is the HHDM alias of the
/// page it copied code into.
///
/// Fails rather than silently succeeding when the architecture cannot
/// re-granularise the mapping. A caller here is about to jump into the page; a
/// quiet "could not, carry on" is the shape of failure that produces a machine
/// which stops with nothing left able to say why.
/// # C: O(pages * walk depth)
/// # Lk: CPA_LOCK acquired
#[cfg(target_os = "oxide-kernel")]
pub fn set_memory_rox(va: u64, pages: u64) -> Result<(), Errno> {
    if pages == 0 { return Ok(()); }
    if !can_set_direct_map() { return Err(Errno::Eopnotsupp); }
    let hhdm = crate::user_as::hhdm_offset();
    if hhdm == 0 { return Err(Errno::Einval); }
    let flags = hal::PageFlags::READ | hal::PageFlags::EXEC;
    // SAFETY: privileged read of the active kernel translation base; the
    // returned root is the tree every CPU walks for kernel addresses.
    let root = unsafe { ArchWalker::read_pt_base(va) };
    {
        let _g = CPA_LOCK.lock();
        for i in 0..pages {
            let page_va = va.wrapping_add(i * hal::PAGE_SIZE_BYTES);
            // SAFETY: the lock makes the kernel tables exclusively ours for this
            // walk; HHDM covers page-table memory; the allocator yields fresh
            // kernel frames the kernel owns outright.
            let split = unsafe {
                hal::pt_walker::split_kernel_leaf_at_root::<ArchWalker, _>(
                    root, page_va, hhdm, || super::alloc_page_table_frame(0))
            };
            match split {
                Ok(()) => {}
                Err(hal::pt_walker::WalkErr::AllocFailed) => return Err(Errno::Enomem),
                Err(_) => return Err(Errno::Einval),
            }
            // SAFETY: same lock, same live root; the rewrite keeps the leaf's
            // output address and replaces only its permissions.
            let n = unsafe {
                hal::pt_walker::protect_4k_at_root::<ArchWalker>(
                    root, page_va, page_va + hal::PAGE_SIZE_BYTES, flags, hhdm)
            };
            // The split guarantees a bottom-level leaf exists, so nothing
            // rewritten means the address is not in the kernel map at all.
            if n == 0 { return Err(Errno::Einval); }
        }
    }
    flush_kernel_range(va, pages * hal::PAGE_SIZE_BYTES);
    Ok(())
}

/// The inverse of [`set_memory_rox`]: writable and never executable, which is
/// what every ordinary page of the linear map is.
///
/// Not an optional tidy-up. A page narrowed to read-only-and-executable and
/// then returned to the page allocator is handed to the next caller with a
/// kernel mapping that faults on the first write — a fault in whatever
/// unrelated subsystem drew the recycled page, arbitrarily far from the code
/// that narrowed it. Every `set_memory_rox` needs this on the release path.
/// # C: O(pages * walk depth)
/// # Lk: CPA_LOCK acquired
#[cfg(target_os = "oxide-kernel")]
pub fn set_memory_rw_nx(va: u64, pages: u64) -> Result<(), Errno> {
    if pages == 0 { return Ok(()); }
    if !can_set_direct_map() { return Ok(()); }
    let hhdm = crate::user_as::hhdm_offset();
    if hhdm == 0 { return Err(Errno::Einval); }
    let flags = hal::PageFlags::READ | hal::PageFlags::WRITE;
    // SAFETY: privileged read of the active kernel translation base.
    let root = unsafe { ArchWalker::read_pt_base(va) };
    {
        let _g = CPA_LOCK.lock();
        for i in 0..pages {
            let page_va = va.wrapping_add(i * hal::PAGE_SIZE_BYTES);
            // SAFETY: same lock, same live root; the rewrite keeps the leaf's
            // output address and replaces only its permissions. No split is
            // attempted: a page this is restoring was split by `set_memory_rox`,
            // and one that was not is already at the map's default.
            unsafe {
                hal::pt_walker::protect_4k_at_root::<ArchWalker>(
                    root, page_va, page_va + hal::PAGE_SIZE_BYTES, flags, hhdm)
            };
        }
    }
    flush_kernel_range(va, pages * hal::PAGE_SIZE_BYTES);
    Ok(())
}

/// Whether every one of `pages` pages at `va` currently permits instruction
/// fetch in kernel mode.
///
/// Separate from [`set_memory_rox`] so a caller can ASSERT the property it
/// depends on rather than assume the rewrite it just asked for had the effect
/// it wanted. The two are not the same claim: the rewrite reports that it
/// found a leaf to change, this reports what the leaf now says.
/// # C: O(pages * walk depth)
/// # Lk: CPA_LOCK acquired
#[cfg(target_os = "oxide-kernel")]
pub fn kernel_range_is_executable(va: u64, pages: u64) -> bool {
    let hhdm = crate::user_as::hhdm_offset();
    if hhdm == 0 { return false; }
    // SAFETY: privileged read of the active kernel translation base.
    let root = unsafe { ArchWalker::read_pt_base(va) };
    let _g = CPA_LOCK.lock();
    (0..pages).all(|i| {
        let page_va = va.wrapping_add(i * hal::PAGE_SIZE_BYTES);
        // SAFETY: read-only walk of the live kernel tables through the HHDM,
        // under the lock that serializes every mutation of them.
        match unsafe { hal::pt_walker::read_leaf_4k_at_root::<ArchWalker>(root, page_va, hhdm) } {
            Some(leaf) => ArchWalker::is_valid(leaf) && leaf_is_kernel_exec(leaf),
            // No bottom-level table covers the address. The mapping is a large
            // leaf this walk cannot read, so the honest answer is "not known to
            // be executable" — and a caller about to jump must treat an unknown
            // as a refusal, not as permission.
            None => false,
        }
    })
}

/// Make a completed linear-map change visible on every CPU. The local
/// invalidate already happened as each leaf was written; this is the remote
/// half, and it targets EVERY online CPU because the kernel's linear map is
/// loaded on all of them — unlike a user mapping, which only needs the CPUs
/// that ran its address space.
/// # C: O(online CPUs) + one interprocessor round trip
#[cfg(target_os = "oxide-kernel")]
pub fn flush_kernel_range(va: u64, len: u64) {
    if len == 0 { return; }
    let targets = cpu::smp::online_mask();
    if len <= hal::PAGE_SIZE_BYTES { hal::tlb::shootdown_others_va(va, targets); }
    else { hal::tlb::shootdown_others_all(targets); }
}

/// Flush the linear-map range covering one page of `pa`.
/// # C: O(online CPUs) + one interprocessor round trip
#[cfg(target_os = "oxide-kernel")]
pub fn flush_kernel_page(pa: u64) { flush_kernel_range(linear_va(pa), hal::PAGE_SIZE_BYTES); }

// The hosted harness has no live kernel page tables to re-granularise. The
// capability query above is real there — it is pure architecture — so the
// decisions that consult it stay checkable without a machine.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn set_direct_map_invalid_noflush(_pa: u64) -> Result<(), Errno> { Ok(()) }
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn set_direct_map_default_noflush(_pa: u64) -> Result<(), Errno> { Ok(()) }
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn kernel_page_present(_pa: u64) -> bool { true }
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn flush_kernel_range(_va: u64, _len: u64) {}
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn set_memory_rox(_va: u64, _pages: u64) -> Result<(), Errno> { Ok(()) }
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn kernel_range_is_executable(_va: u64, _pages: u64) -> bool { true }
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn set_memory_rw_nx(_va: u64, _pages: u64) -> Result<(), Errno> { Ok(()) }
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn flush_kernel_page(_pa: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capability is delegated whole to the architecture, which answers it
    /// from every mechanism it has — an on-demand granularity change of a live
    /// kernel mapping, or a map whose RAM was built page-granular so no change
    /// is needed. Deciding it here from the size a large leaf happens to have
    /// would answer "no" on a machine that can do it perfectly well, and the
    /// only visible effect is that a syscall whose entire contract depends on
    /// it reports itself unimplemented.
    #[test]
    fn capability_is_answered_by_the_architecture_not_by_a_leaf_size() {
        let large_leaf = 1u64 << 30;
        assert_ne!(large_leaf, hal::PAGE_SIZE_BYTES);
        assert_eq!(can_set_direct_map(), ArchWalker::can_split_kernel_leaf());
    }

    #[test]
    fn this_architecture_can_remove_pages_from_the_linear_map() {
        // The hosted harness builds for the same architecture as the x86 kernel
        // target, whose page-attribute machinery re-granularises on demand.
        assert!(can_set_direct_map());
    }
}
