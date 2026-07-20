//! Live swapoff migration: collect PTEs under locks, restore outside them.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::*;

/// One pinned address-space swap-PTE migration request.
struct SwapPte {
    mm: Arc<AddressSpace>,
    va: u64,
    entry: hal::pt_walker::SwapEntry,
}

/// Drain every PTE referencing `kind`, then remove the empty canonical area.
/// New page-out allocation is excluded for the full migration by the PMM
/// drain flag. Partial progress remains valid on failure: restored PTEs stay
/// resident and unmatched slots remain in the still-active area.
/// # C: O(all live user page tables + swapped pages * page I/O)
pub fn drain_swap_area(kind: u8) -> Result<(), vmm::Error> {
    crate::swap::begin_drain(kind).map_err(swap_error)?;
    loop {
        let work = match collect_swap_ptes(kind) {
            Ok(work) => work,
            Err(error) => { crate::swap::cancel_drain(kind); return Err(error); }
        };
        for item in work {
            let uva = match UserVirtAddr::new(item.va) {
                Some(uva) => uva,
                None => { crate::swap::cancel_drain(kind); return Err(vmm::Error::Inval); }
            };
            if let Err(error) = super::swap_in::restore_swap_entry(&item.mm, uva, item.entry, None, hhdm_offset()) {
                crate::swap::cancel_drain(kind);
                return Err(error);
            }
        }
        match crate::swap::finish_drain(kind) {
            Ok(()) => return Ok(()),
            // A stale scan, an unpublished fork child, or a pageout that
            // started before begin_drain can leave live slots after this pass.
            // Linux try_to_unuse rescans in precisely this situation; EBUSY is
            // reserved for another swapoff owner, not ordinary mm mutation.
            Err(crate::swap::SwapError::Busy) => drain_resched(),
            Err(error) => { crate::swap::cancel_drain(kind); return Err(swap_error(error)); }
        }
    }
}

/// Voluntarily give an in-flight pageout/fork owner a chance to publish or
/// roll back its leaf before the next canonical live-mm scan.
fn drain_resched() {
    #[cfg(target_os = "oxide-kernel")]
    if sched::live::global().is_some() {
        // SAFETY: swapoff runs in process context and holds no PMM/VMM lock
        // across this call; the syscall path is preempt-disabled like the
        // canonical sched_yield implementation.
        unsafe { sched::live::sched_yield(); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    core::hint::spin_loop();
}

/// Snapshot all PTEs for one swap area while each owning PTE lock is held.
/// The returned `Arc`s pin their address spaces through I/O and checked PTE
/// replacement, while no page-table lock is held across a blocking operation.
/// # C: O(all live user page tables)
fn collect_swap_ptes(kind: u8) -> Result<Vec<SwapPte>, vmm::Error> {
    let spaces = vmm::address_space::live_address_spaces()?;
    let mut work = Vec::<SwapPte>::new();
    for mm in spaces {
        let _pt = mm.lock_page_table();
        let mut allocation_failed = false;
        // SAFETY: the PTE lock is held, the mm Arc pins its root, and HHDM
        // covers all page-table frames.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            hal::pt_walker::walk_user_swap_entries_at_root::<hal_x86_64::vmm::PtWalkerX86, _>(mm.root_pa(), hhdm_offset(), |va, entry| {
                if entry.kind() == kind && !allocation_failed {
                    if work.try_reserve(1).is_err() { allocation_failed = true; }
                    else { work.push(SwapPte { mm: Arc::clone(&mm), va, entry }); }
                }
            });
            #[cfg(target_arch = "aarch64")]
            hal::pt_walker::walk_user_swap_entries_at_root::<hal_aarch64::vmm::PtWalkerArm, _>(mm.root_pa(), hhdm_offset(), |va, entry| {
                if entry.kind() == kind && !allocation_failed {
                    if work.try_reserve(1).is_err() { allocation_failed = true; }
                    else { work.push(SwapPte { mm: Arc::clone(&mm), va, entry }); }
                }
            });
        }
        if allocation_failed { return Err(vmm::Error::NoMem); }
    }
    Ok(work)
}

/// # C: O(1)
fn swap_error(error: crate::swap::SwapError) -> vmm::Error {
    match error {
        crate::swap::SwapError::NoMem => vmm::Error::NoMem,
        crate::swap::SwapError::Io => vmm::Error::Io,
        crate::swap::SwapError::Busy | crate::swap::SwapError::Inval
        | crate::swap::SwapError::NoSpace | crate::swap::SwapError::NoSuchArea => vmm::Error::Inval,
    }
}
