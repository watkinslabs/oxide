//! Direct reclaim of exclusively mapped anonymous pages into canonical swap.

use super::*;

use alloc::vec::Vec;

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
const PAGE_MASK: u64 = PAGE_BYTES - 1;
const FIRST_RECLAIM_MAPPING: usize = 1;
const NO_RECLAIMED_MAPPINGS: usize = 0;

/// One pinned source PTE in a page-out transaction.
struct ReclaimPte {
    mm: Arc<AddressSpace>,
    va: u64,
    original_flags: hal::PageFlags,
    protected: bool,
    replaced: bool,
}

/// Reclaim one inactive anonymous LRU page when the buddy allocator is empty.
///
/// LRU isolation is completed before the page lock or any address-space lock
/// is taken. A failed transaction puts the page back on its original list;
/// only a fully converted rmap set consumes the isolation token. This keeps
/// direct reclaim out of the PMM-wide PFN scan and prevents an allocator
/// retry from observing a partially reclaimed page. # C: O(rmap mappings + one page I/O)
pub(crate) fn reclaim_one_anon_page() -> bool {
    if !crate::swap::has_writable_area() { return false; }
    let isolated = match crate::setup::isolate_inactive_anon_lru() {
        Ok(Some(isolated)) => isolated,
        Ok(None) | Err(_) => return false,
    };
    reclaim_isolated_anon_page(isolated)
}

/// Reclaim one inactive anonymous page owned by `memcg`.  Used by the
/// memcg pressure transaction after a real high/max transition; it shares the
/// exact rmap-verified pageout path with global direct reclaim.
/// # C: O(N_inactive_anon + rmap mappings + one page I/O)
pub(crate) fn reclaim_one_anon_page_memcg(memcg: u64) -> bool {
    if !crate::swap::has_writable_area() { return false; }
    let isolated = match crate::setup::isolate_inactive_anon_lru_memcg(memcg) {
        Ok(Some(isolated)) => isolated,
        Ok(None) | Err(_) => return false,
    };
    reclaim_isolated_anon_page(isolated)
}

/// Execute one page-out transaction after a reclaim owner isolated an anon
/// LRU member. The LRU lock is never held across the page lock, rmap walk, or
/// page-table locks, preserving the PMM lock order.
fn reclaim_isolated_anon_page(isolated: crate::reclaim::Isolation) -> bool {
    let pa = isolated.pfn().0 * PAGE_BYTES;
    if !crate::setup::try_lock_page(pa) {
        let _ = crate::setup::putback_isolated_lru(isolated);
        return false;
    }
    let reclaimed = reclaim_locked_anon_page(pa);
    if reclaimed == NO_RECLAIMED_MAPPINGS {
        crate::kassert!(crate::setup::putback_isolated_lru(isolated).is_ok(), "reclaim putback lru invariant");
        let _ = crate::setup::unlock_page(pa);
        return false;
    }
    // All source PTEs are now non-present swap leaves. Drop LRU ownership
    // before the matching PTE references can reach final PMM free below.
    crate::kassert!(crate::setup::release_isolated_lru(isolated).is_ok(), "reclaim release lru invariant");
    let _ = crate::setup::unlock_page(pa);
    // The source PTEs are all non-present before their physical references
    // are released. `rmap_aware_dec...` takes the page lock itself, hence it
    // must run only after the transaction's lock has been dropped.
    for _ in NO_RECLAIMED_MAPPINGS..reclaimed {
        // SAFETY: one exact source PTE was replaced by a swap PTE per loop.
        unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
    }
    true
}

/// Apply Linux `MADV_PAGEOUT` to the anonymous resident pages in one VMA
/// range. Each candidate enters the exact same rmap-verified transaction as
/// allocator direct reclaim; an absent, shared, locked, or already-swapped
/// page is a permitted best-effort skip. # C: O(pages · rmap mappings)
pub fn pageout_anon_range(as_: &AddressSpace, start: u64, len: u64) -> i64 {
    let Some(end) = start.checked_add(len) else { return 0; };
    let mut va = start;
    while va < end {
        let pa = {
            // SAFETY: `as_` owns this live page-table root; the walker reads
            // one aligned user leaf through the established HHDM mapping.
            unsafe { super::foreign::read_foreign_leaf_pa(as_.root_pa(), va, hhdm_offset()) }
        };
        if let Some(pa) = pa {
            let pa = pa & !PAGE_MASK;
            if let Ok(Some(isolated)) = crate::setup::isolate_anon_lru_pfn(pa) {
                let _ = reclaim_isolated_anon_page(isolated);
            }
        }
        va = match va.checked_add(PAGE_BYTES) { Some(next) => next, None => break };
    }
    0
}

fn reclaim_locked_anon_page(pa: u64) -> usize {
    let mut ptes = Vec::<ReclaimPte>::new();
    let mut allocation_failed = false;
    let mapped = super::foreign::rmap_walk_anon_pa_with_mm(pa, |mm, va| {
        if allocation_failed { return; }
        if ptes.try_reserve(FIRST_RECLAIM_MAPPING).is_err() {
            allocation_failed = true;
            return;
        }
        let Some(uva) = UserVirtAddr::new(va) else { return; };
        let Some(vma) = mm.find_vma(uva) else { return; };
        if !matches!(vma.backing, VmaBacking::Anonymous) { return; }
        ptes.push(ReclaimPte {
            mm: Arc::clone(mm), va, original_flags: vma.prot.to_page_flags(),
            protected: false, replaced: false,
        });
    });
    // Reclaim is opportunistic. It must not mutate permissions unless it has
    // retained the exact original flags required to roll an aborted
    // transaction back. Under allocator pressure, defer this candidate.
    if allocation_failed { return NO_RECLAIMED_MAPPINGS; }
    if mapped != ptes.len() || ptes.is_empty() {
        return NO_RECLAIMED_MAPPINGS;
    }
    for pte in ptes.iter_mut() {
        let mut write_protected_flags = pte.original_flags;
        write_protected_flags.remove(hal::PageFlags::WRITE);
        pte.protected = {
            let _pt = pte.mm.lock_page_table();
        // SAFETY: the PTE lock is held; exact-PA validation closes the rmap
        // snapshot race before the permission downgrade.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            { hal::pt_walker::replace_present_4k_flags_if_pa_at_root::<hal_x86_64::vmm::PtWalkerX86>(pte.mm.root_pa(), pte.va, pa, write_protected_flags, hhdm_offset()) }
            #[cfg(target_arch = "aarch64")]
            { hal::pt_walker::replace_present_4k_flags_if_pa_at_root::<hal_aarch64::vmm::PtWalkerArm>(pte.mm.root_pa(), pte.va, pa, write_protected_flags, hhdm_offset()) }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            { false }
        }
        };
        if !pte.protected {
            restore_unreplaced_mappings(&ptes, pa);
            return NO_RECLAIMED_MAPPINGS;
        }
        flush_reclaim_mapping(&pte.mm, pte.va);
    }

    // SAFETY: every source mapping is now read-only and its TLB invalidated,
    // so copying through the HHDM cannot race a user-space writer.
    let page = unsafe {
        core::slice::from_raw_parts((hhdm_offset() + pa) as *const u8, PAGE_BYTES as usize)
    };
    let memcg = crate::setup::memcg_for_pa(pa);
    if memcg == cgroup::NO_MEMCG {
        // An anonymous rmap page is created with PageMeta memcg ownership.
        // Reassigning a missing owner to root would create a second truth, so
        // leave this candidate resident and retain a diagnosable invariant.
        #[cfg(feature = "debug-pmm")]
        {
            klog::write_raw(b"[PMM-RECLAIM] unowned anonymous page pa=");
            klog::write_hex_u64(pa);
            klog::write_raw(b"\n");
        }
        restore_unreplaced_mappings(&ptes, pa);
        return NO_RECLAIMED_MAPPINGS;
    }
    if !cgroup::try_charge_swap(memcg, PAGE_BYTES) {
        restore_unreplaced_mappings(&ptes, pa);
        return NO_RECLAIMED_MAPPINGS;
    }
    let entry = match crate::swap::store_page(page, memcg) {
        Ok(entry) => entry,
        Err(_) => {
            cgroup::uncharge_swap(memcg, PAGE_BYTES);
            restore_unreplaced_mappings(&ptes, pa);
            return NO_RECLAIMED_MAPPINGS;
        }
    };
    // Allocate every eventual PTE reference before touching the first leaf.
    // A retain failure therefore leaves all mappings resident and permits an
    // ordinary permission rollback instead of a partial swap conversion.
    let mut slot_refs = FIRST_RECLAIM_MAPPING;
    for _ in FIRST_RECLAIM_MAPPING..ptes.len() {
        if crate::swap::retain_page(entry).is_err() {
            for _ in NO_RECLAIMED_MAPPINGS..slot_refs {
                let _ = crate::swap::free_page(entry);
            }
            restore_unreplaced_mappings(&ptes, pa);
            return NO_RECLAIMED_MAPPINGS;
        }
        slot_refs += FIRST_RECLAIM_MAPPING;
    }
    for pte in ptes.iter_mut() {
        pte.replaced = replace_mapping_with_swap(pte, pa, entry);
        if pte.replaced {
            let uva = UserVirtAddr::new(pte.va).expect("reclaim pte va invariant");
            pte.mm.account_present_to_swap_at(uva);
            flush_reclaim_mapping(&pte.mm, pte.va);
            continue;
        }
        rollback_replaced_mappings(&ptes, pa, entry);
        for _ in NO_RECLAIMED_MAPPINGS..ptes.len() {
            let _ = crate::swap::free_page(entry);
        }
        restore_unreplaced_mappings(&ptes, pa);
        return NO_RECLAIMED_MAPPINGS;
    }
    let reclaimed = ptes.len();
    #[cfg(feature = "debug-pmm")]
    {
        klog::write_raw(b"[PMM-RECLAIM] pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b" mappings=");
        klog::write_dec_u64(reclaimed as u64);
        klog::write_raw(b" swap-kind=");
        klog::write_dec_u64(entry.kind() as u64);
        klog::write_raw(b" slot=");
        klog::write_dec_u64(entry.offset());
        klog::write_raw(b"\n");
    }
    reclaimed
}

fn replace_mapping_with_swap(pte: &ReclaimPte, pa: u64, entry: hal::pt_walker::SwapEntry) -> bool {
    let _pt = pte.mm.lock_page_table();
    // SAFETY: the PTE lock is held; replacement requires the exact source
    // frame that was write-protected before I/O.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { hal::pt_walker::replace_present_4k_with_swap_if_pa_at_root::<hal_x86_64::vmm::PtWalkerX86>(pte.mm.root_pa(), pte.va, pa, entry, hhdm_offset()).is_some() }
        #[cfg(target_arch = "aarch64")]
        { hal::pt_walker::replace_present_4k_with_swap_if_pa_at_root::<hal_aarch64::vmm::PtWalkerArm>(pte.mm.root_pa(), pte.va, pa, entry, hhdm_offset()).is_some() }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { false }
    }
}

fn restore_unreplaced_mappings(ptes: &[ReclaimPte], pa: u64) {
    for pte in ptes.iter().filter(|pte| pte.protected && !pte.replaced) {
        let _pt = pte.mm.lock_page_table();
    // SAFETY: the PTE lock is held.  Exact-PA validation avoids restoring
    // permissions on a page installed by a concurrent fault or remap.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { let _ = hal::pt_walker::replace_present_4k_flags_if_pa_at_root::<hal_x86_64::vmm::PtWalkerX86>(pte.mm.root_pa(), pte.va, pa, pte.original_flags, hhdm_offset()); }
        #[cfg(target_arch = "aarch64")]
        { let _ = hal::pt_walker::replace_present_4k_flags_if_pa_at_root::<hal_aarch64::vmm::PtWalkerArm>(pte.mm.root_pa(), pte.va, pa, pte.original_flags, hhdm_offset()); }
    }
        flush_reclaim_mapping(&pte.mm, pte.va);
    }
}

/// Restore every swap leaf written by an aborted transaction. A replacement
/// failure is recoverable only while every already-published leaf still names
/// this exact entry; otherwise a concurrent owner violated the page-lock
/// transaction and continuing would leave split resident/swap truth.
fn rollback_replaced_mappings(ptes: &[ReclaimPte], pa: u64, entry: hal::pt_walker::SwapEntry) {
    for pte in ptes.iter().filter(|pte| pte.replaced) {
        let _pt = pte.mm.lock_page_table();
        let restored = unsafe {
            // SAFETY: the PTE lock is held and this transaction installed the
            // exact swap entry after write-protecting the original PA.
            #[cfg(target_arch = "x86_64")]
            { hal::pt_walker::replace_swap_4k_with_present_at_root::<hal_x86_64::vmm::PtWalkerX86>(pte.mm.root_pa(), pte.va, entry, pa, pte.original_flags, hhdm_offset()) }
            #[cfg(target_arch = "aarch64")]
            { hal::pt_walker::replace_swap_4k_with_present_at_root::<hal_aarch64::vmm::PtWalkerArm>(pte.mm.root_pa(), pte.va, entry, pa, pte.original_flags, hhdm_offset()) }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            { false }
        };
        crate::kassert!(restored, "reclaim swap rollback invariant");
        let uva = UserVirtAddr::new(pte.va).expect("reclaim rollback va invariant");
        pte.mm.account_swap_to_present_at(uva);
        flush_reclaim_mapping(&pte.mm, pte.va);
    }
}

/// Invalidate one PTE transition on every CPU currently running `mm`.
/// Reclaim owners that replace a present page with a non-present transient
/// state must use this before copying or releasing the old frame. # C: O(CPUs)
pub fn flush_reclaim_mapping(mm: &AddressSpace, va: u64) {
    let current_root = sched::live::current()
        .and_then(|task| unsafe { task.mm_ref() })
        .map(|current_mm| current_mm.root_pa());
    if current_root == Some(mm.root_pa()) {
        // SAFETY: this CPU currently runs `mm`; invalidate its just-mutated VA.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::flush_local_va(va); }
            #[cfg(target_arch = "aarch64")]
            { <hal_aarch64::mmu_ops::ArmMmu as hal::MmuOps>::flush_va(hal::Va(va)); }
        }
    }
    hal::tlb::shootdown_others_va(va, mm.cpumask());
}
