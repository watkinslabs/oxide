//! Page-table ownership for Linux-shaped `mremap` moves.
//!
//! The VMM owns VMA policy, but only PMM owns the live page-table root and the
//! references represented by its leaves. A move therefore transfers raw PTEs
//! here; it never reads or writes the user virtual addresses.

use alloc::vec::Vec;

use hal::{MmuOps, Va};

use super::current_mm_cpumask_full;

/// Move `[old, old + len)` to `new` in the current address space.
///
/// Sparse holes remain holes, and every non-empty leaf keeps its exact raw
/// encoding. A failed allocation rolls already-moved leaves back before the
/// caller sees the error. The VMA write owner must serialize this with every
/// other mapping mutation; this function only owns the page-table side.
/// # C: O(len / PAGE_SIZE)
pub fn move_pages(old: u64, new: u64, len: u64) -> Result<(), vmm::Error> {
    let page = hal::PAGE_SIZE_BYTES;
    if len == 0 || old % page != 0 || new % page != 0 {
        return Err(vmm::Error::Inval);
    }
    let old_end = old.checked_add(len).ok_or(vmm::Error::Inval)?;
    let new_end = new.checked_add(len).ok_or(vmm::Error::Inval)?;
    if old < new_end && new < old_end {
        return Err(vmm::Error::Inval);
    }
    let cur = sched::live::current().ok_or(vmm::Error::Inval)?;
    // SAFETY: syscall context owns the current task's mm slot for this
    // mutation; the Arc keeps the root alive through the page-table walk.
    let mm = unsafe { cur.mm_ref() }.ok_or(vmm::Error::Inval)?.clone();
    let _pt = mm.lock_page_table();
    let mut moved = Vec::new();
    let mut off = 0u64;
    while off < len {
        let result = {
            #[cfg(target_arch = "x86_64")]
            { unsafe { hal_x86_64::mmu_ops::X86Mmu::move_leaf_at(mm.root_pa(), Va(old + off), Va(new + off)) } }
            #[cfg(target_arch = "aarch64")]
            { unsafe { hal_aarch64::mmu_ops::ArmMmu::move_leaf_at(mm.root_pa(), Va(old + off), Va(new + off)) } }
        };
        match result {
            Ok(Some(size)) => {
                let bytes = size.bytes() as u64;
                if off + bytes > len {
                    for (prior, _) in moved.into_iter().rev() {
                        #[cfg(target_arch = "x86_64")]
                        { let _ = unsafe { hal_x86_64::mmu_ops::X86Mmu::move_leaf_at(mm.root_pa(), Va(new + prior), Va(old + prior)) }; }
                        #[cfg(target_arch = "aarch64")]
                        { let _ = unsafe { hal_aarch64::mmu_ops::ArmMmu::move_leaf_at(mm.root_pa(), Va(new + prior), Va(old + prior)) }; }
                    }
                    return Err(vmm::Error::Inval);
                }
                moved.push((off, size));
                off += bytes;
            }
            Ok(None) => off += page,
            Err(hal::pt_walker::WalkErr::HitHugeOrBlock) => {
                for (prior, _) in moved.into_iter().rev() {
                    #[cfg(target_arch = "x86_64")]
                    { let _ = unsafe { hal_x86_64::mmu_ops::X86Mmu::move_leaf_at(mm.root_pa(), Va(new + prior), Va(old + prior)) }; }
                    #[cfg(target_arch = "aarch64")]
                    { let _ = unsafe { hal_aarch64::mmu_ops::ArmMmu::move_leaf_at(mm.root_pa(), Va(new + prior), Va(old + prior)) }; }
                }
                return Err(vmm::Error::Inval);
            }
            Err(_) => {
                for (prior, _) in moved.into_iter().rev() {
                    #[cfg(target_arch = "x86_64")]
                    { let _ = unsafe { hal_x86_64::mmu_ops::X86Mmu::move_leaf_at(mm.root_pa(), Va(new + prior), Va(old + prior)) }; }
                    #[cfg(target_arch = "aarch64")]
                    { let _ = unsafe { hal_aarch64::mmu_ops::ArmMmu::move_leaf_at(mm.root_pa(), Va(new + prior), Va(old + prior)) }; }
                }
                return Err(vmm::Error::NoMem);
            }
        }
    }
    let mask = current_mm_cpumask_full();
    for &(at, size) in &moved {
        // A native block leaf may cover many base pages. Invalidate every
        // base-page address in that span because the generic shootdown API
        // carries one VA, not a size.
        let mut within = 0u64;
        while within < size.bytes() {
            let old_va = old + at + within;
            let new_va = new + at + within;
            // The active CPU may have cached either side before the move;
            // peers need the same invalidation before the old mapping can be
            // reused.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(old_va); hal_x86_64::flush_local_va(new_va); }
            #[cfg(target_arch = "aarch64")]
            unsafe { hal_aarch64::flush_local_va(old_va); hal_aarch64::flush_local_va(new_va); }
            hal::tlb::shootdown_others_va(old_va, mask.as_words());
            hal::tlb::shootdown_others_va(new_va, mask.as_words());
            within += page;
        }
    }
    let _ = (old_end, new_end);
    Ok(())
}
