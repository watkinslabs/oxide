//! One authoritative restoration path for faulted and swapoff-migrated PTEs.

use super::*;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// Restore `entry` into a fresh RAM frame at `uva`. A fault passes its access
/// mode for VMA permission enforcement; swapoff passes `None` because an
/// existing swap PTE is migrated without a user access attempt.
/// Returns true when the PTE was restored or a concurrent winner made the
/// request stale; the caller can then continue normally.
/// # C: O(page I/O + walk depth)
pub(super) fn restore_swap_entry(
    as_: &AddressSpace, uva: UserVirtAddr, entry: hal::pt_walker::SwapEntry,
    access: Option<FaultAccess>, hhdm: u64,
) -> Result<bool, vmm::Error> {
    let va_page = uva.as_u64() & !PAGE_MASK;
    let vma = as_.find_vma(uva).ok_or(vmm::Error::Inval)?;
    if !matches!(vma.backing, VmaBacking::Anonymous) { return Err(vmm::Error::Inval); }
    if access.is_some_and(|access| !vma.permits(access)) { return Err(vmm::Error::Inval); }
    // An anonymous swapped page must rejoin its original anonymous reverse-map
    // family. Refuse corrupted VMA metadata before moving the canonical memcg
    // charge from its swap slot back to a resident PageMeta owner.
    let anon_vma = vma.anon_vma.as_ref().ok_or(vmm::Error::Inval)?;
    let memcg = crate::swap::memcg(entry).map_err(|_| vmm::Error::Io)?;
    if !cgroup::try_charge_memcg(memcg, PAGE_BYTES) { return Err(vmm::Error::NoMem); }
    let pa = match crate::setup::alloc_one_frame() {
        Some(pa) => pa,
        None => {
            cgroup::uncharge_memcg(memcg, PAGE_BYTES);
            return Err(vmm::Error::NoMem);
        }
    };
    // SAFETY: `pa` is a fresh full page and HHDM maps physical memory writable.
    let page = unsafe {
        core::slice::from_raw_parts_mut((hhdm + pa) as *mut u8, PAGE_BYTES as usize)
    };
    if crate::swap::load_page(entry, page).is_err() {
        // SAFETY: allocation is not visible in any PTE after failed I/O.
        unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
        cgroup::uncharge_memcg(memcg, PAGE_BYTES);
        return Err(vmm::Error::Io);
    }
    let flags = vma.prot.to_page_flags();
    let index = ((va_page - vma.start.as_u64()) / PAGE_BYTES) as u32;
    // SAFETY: fresh `pa` is not PTE-visible until the checked commit below.
    unsafe { crate::setup::set_anon_rmap_for_pa(pa, anon_vma, index); }
    crate::setup::set_memcg_for_pa(pa, memcg);
    let installed = {
        let _pt = as_.lock_page_table();
        // SAFETY: PTE lock is held; the helper checks this exact entry before replacement.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            { hal::pt_walker::replace_swap_4k_with_present_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va_page, entry, pa, flags, hhdm) }
            #[cfg(target_arch = "aarch64")]
            { hal::pt_walker::replace_swap_4k_with_present_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va_page, entry, pa, flags, hhdm) }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            { false }
        }
    };
    if !installed {
        // SAFETY: no PTE references `pa`; drop the provisional rmap and frame.
        unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
        // The provisional RAM charge was acquired before I/O. A stale
        // compare-and-replace owns no present PTE, so it must roll that charge
        // back with the provisional frame instead of leaking it into memcg.
        cgroup::uncharge_memcg(memcg, PAGE_BYTES);
        return Ok(true);
    }
    as_.account_swap_to_present_at(uva);
    // The replacement PTE is now durable and this page has complete anon
    // PageMeta+rmap+memcg ownership.  Only this successful path may admit it;
    // a stale swap-fault loser freed its provisional frame above.
    kassert!(crate::setup::admit_anon_lru(pa).is_ok(), "swapin anon lru admission invariant");
    hal::tlb::shootdown_others_va(va_page, as_.cpumask());
    // The present PTE is durable before releasing its old swap slot.
    let _ = crate::swap::free_page(entry);
    Ok(true)
}

/// Restore one exact parent swap leaf after fork observes its area draining.
/// The checked replacement makes a concurrent fault/unmap harmless: stale
/// work is success because no child reference was admitted for this entry.
/// # C: O(page I/O + walk depth)
pub fn restore_swap_for_fork(
    as_: &AddressSpace, va: u64, entry: hal::pt_walker::SwapEntry,
) -> Result<(), vmm::Error> {
    let uva = UserVirtAddr::new(va).ok_or(vmm::Error::Inval)?;
    let _ = restore_swap_entry(as_, uva, entry, None, hhdm_offset())?;
    Ok(())
}
