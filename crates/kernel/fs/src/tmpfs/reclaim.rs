//! Tmpfs/shmem shrinker: the inode page index remains the sole data owner.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, TaskList};
use vfs::{KResult, VfsError};

use super::file::{ShmemPage, TmpfsFileData};

#[cfg(test)]
use core::sync::atomic::{AtomicBool, Ordering};

// These switches are deliberately test-only: they exercise the two recovery
// paths below without changing the kernel's migration or swap contracts.
#[cfg(test)]
static FAIL_NEXT_MARKER: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static FAIL_NEXT_STORE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(super) fn fail_next_marker_for_test() { FAIL_NEXT_MARKER.store(true, Ordering::Release); }
#[cfg(test)]
pub(super) fn fail_next_store_for_test() { FAIL_NEXT_STORE.store(true, Ordering::Release); }
#[cfg(test)]
pub(super) fn attach_marker_for_test(token: hal::pt_walker::MigrationEntry) -> bool { attach_marker(token) }
#[cfg(test)]
pub(super) fn store_page_for_test(bytes: &[u8], cgid: u64) -> Option<hal::pt_walker::SwapEntry> {
    store_page(bytes, cgid)
}

fn attach_marker(token: hal::pt_walker::MigrationEntry) -> bool {
    #[cfg(test)]
    if FAIL_NEXT_MARKER.swap(false, Ordering::AcqRel) { return false; }
    vmm::migration_attach_marker(token)
}

fn store_page(bytes: &[u8], cgid: u64) -> Option<hal::pt_walker::SwapEntry> {
    #[cfg(test)]
    if FAIL_NEXT_STORE.swap(false, Ordering::AcqRel) { return None; }
    pmm::swap::store_page(bytes, cgid).ok()
}

struct FrozenPte {
    mm: Arc<vmm::AddressSpace>, va: u64, flags: hal::PageFlags,
}

fn hhdm_offset() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    { pmm::user_as::hhdm_offset() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Flush one mapping after a migration-leaf transition. Hosted fixtures have
/// no live CPUs or hardware TLB, while the kernel path reuses PMM's canonical
/// targeted shootdown implementation. # C: O(CPUs)
fn flush_mapping(mm: &vmm::AddressSpace, va: u64) {
    #[cfg(target_os = "oxide-kernel")]
    pmm::user_as::flush_reclaim_mapping(mm, va);
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = (mm, va); }
}

fn freeze_mapped_page(data: &TmpfsFileData, idx: u64, pa: u64, cgid: u64) -> Option<(hal::pt_walker::MigrationEntry, Vec<FrozenPte>)> {
    let rmap = pmm::setup::file_rmap_for_pa(pa)?;
    let token = vmm::migration_begin(pa)?;
    {
        let mut pages = data.pages.lock();
        match pages.get(&idx).copied() {
            Some(ShmemPage::Resident { pa: current, cgid: owner }) if current == pa && owner == cgid => {
                pages.insert(idx, ShmemPage::Migrating { pa, cgid, token });
                #[cfg(feature = "debug-zram-lifecycle")]
                super::lifetime::trace_migration(b"freeze", data, idx, token);
            }
            _ => { let _ = vmm::migration_finish(token); return None; }
        }
    }
    let mut frozen = Vec::new();
    let mut oom = false;
    if rmap.walk_page(idx, |mm, va| {
        let Some(uva) = hal::UserVirtAddr::new(va) else { return; };
        let Some(vma) = mm.find_vma(uva) else { return; };
        if !vma.file_rmap.as_ref().is_some_and(|owner| Arc::ptr_eq(owner, &rmap)) { return; }
        let file_idx = match &vma.backing { vmm::VmaBacking::File { off, .. } =>
            (off + va - vma.start.as_u64()) / hal::PAGE_SIZE_BYTES, _ => return };
        if file_idx != idx || frozen.try_reserve(1).is_err() { oom = true; return; }
        let _pt = mm.lock_page_table();
        if !attach_marker(token) { oom = true; return; }
        #[cfg(target_arch = "x86_64")]
        let changed = unsafe { hal::pt_walker::replace_present_4k_with_migration_if_pa_at_root::<hal_x86_64::vmm::PtWalkerX86>(mm.root_pa(), va, pa, token, hhdm_offset()) };
        #[cfg(target_arch = "aarch64")]
        let changed = unsafe { hal::pt_walker::replace_present_4k_with_migration_if_pa_at_root::<hal_aarch64::vmm::PtWalkerArm>(mm.root_pa(), va, pa, token, hhdm_offset()) };
        drop(_pt);
        if changed {
            flush_mapping(&mm, va);
            frozen.push(FrozenPte { mm, va, flags: vma.prot.to_page_flags() });
        }
        else { let _ = vmm::migration_restore_marker_mapping(token); }
    }).is_err() { oom = true; }
    if oom {
        rollback_frozen_page(data, idx, pa, cgid, token, frozen);
        return None;
    }
    Some((token, frozen))
}

fn rollback_frozen_page(data: &TmpfsFileData, idx: u64, pa: u64, cgid: u64, token: hal::pt_walker::MigrationEntry, frozen: Vec<FrozenPte>) {
    for pte in frozen {
        let _pt = pte.mm.lock_page_table();
        #[cfg(target_arch = "x86_64")]
        let restored = unsafe { hal::pt_walker::replace_migration_4k_with_present_at_root::<hal_x86_64::vmm::PtWalkerX86>(pte.mm.root_pa(), pte.va, token, pa, pte.flags, hhdm_offset()) };
        #[cfg(target_arch = "aarch64")]
        let restored = unsafe { hal::pt_walker::replace_migration_4k_with_present_at_root::<hal_aarch64::vmm::PtWalkerArm>(pte.mm.root_pa(), pte.va, token, pa, pte.flags, hhdm_offset()) };
        drop(_pt);
        if restored {
            flush_mapping(&pte.mm, pte.va);
            let _ = vmm::migration_restore_marker_mapping(token);
        }
    }
    let mut pages = data.pages.lock();
    if matches!(pages.get(&idx), Some(ShmemPage::Migrating { token: current, .. }) if *current == token) {
        pages.insert(idx, ShmemPage::Resident { pa, cgid });
        #[cfg(feature = "debug-zram-lifecycle")]
        super::lifetime::trace_migration(b"rollback", data, idx, token);
    }
    drop(pages);
    let _ = vmm::migration_finish(token);
    #[cfg(target_os = "oxide-kernel")]
    sched::live::migration_wait::wake(token.token());
}

#[cfg(test)]
pub(super) fn rollback_mapped_for_test(
    data: &TmpfsFileData, idx: u64, pa: u64, cgid: u64, token: hal::pt_walker::MigrationEntry,
) {
    rollback_frozen_page(data, idx, pa, cgid, token, Vec::new());
}

static OBJECTS: Spinlock<Vec<Weak<TmpfsFileData>>, TaskList> = Spinlock::new(Vec::new());
static INSTALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Install the one tmpfs shrinker.  The weak index is an enumeration aid only;
/// every resident/swap decision remains in `TmpfsFileData.pages`.
/// # C: O(1)
pub(super) fn install() {
    use core::sync::atomic::Ordering;
    if INSTALLED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    let shrinker = pmm::shrinker::Shrinker { count_objects, scan_objects };
    if pmm::shrinker::register_shrinker(shrinker).is_err() {
        INSTALLED.store(false, Ordering::Release);
    }
}

/// Publish an inode-owned page index to the tmpfs shrinker. # C: amortised O(1)
pub(super) fn register(data: &Arc<TmpfsFileData>) {
    let mut objects = OBJECTS.lock();
    if objects.iter().any(|weak| weak.upgrade().is_some_and(|live| Arc::ptr_eq(&live, data))) { return; }
    if objects.try_reserve(1).is_ok() { objects.push(Arc::downgrade(data)); }
}

fn live_objects() -> Vec<Arc<TmpfsFileData>> {
    let mut objects = OBJECTS.lock();
    let mut live = Vec::new();
    for weak in objects.iter() {
        if let Some(data) = weak.upgrade() { live.push(data); }
    }
    objects.retain(|weak| weak.upgrade().is_some());
    live
}

/// Number of shmem pages eligible for either unmapped eviction or the mapped
/// rmap transaction.  An in-flight `Migrating` index entry is never a second
/// candidate: its original reclaimer is the token's only owner.
/// # C: O(all live tmpfs page indices)
fn count_objects() -> usize {
    live_objects().iter().map(|data| data.pages.lock().values().filter(|page| {
        matches!(*page, ShmemPage::Resident { .. })
    }).count()).sum()
}

/// Linux `shmem_writepage`-shaped eviction for an *unmapped* object page.
/// The swap entry replaces the resident entry at the SAME inode index.  It
/// never calls anonymous rmap/pageout and cannot drop mapped shared data.
/// # C: O(page indices + one swap I/O)
fn scan_objects(target: usize) -> usize {
    let mut released = 0usize;
    for data in live_objects() {
        while released < target {
            if evict_one_unmapped(&data) || evict_one_mapped(&data) { released += 1; } else { break; }
        }
        if released == target { break; }
    }
    released
}

fn candidate(data: &TmpfsFileData) -> Option<(u64, u64, u64)> {
    data.pages.lock().iter().find_map(|(&idx, page)| match *page {
        ShmemPage::Resident { pa, cgid } if pmm::setup::frame_mapcount(pa) == 0 => Some((idx, pa, cgid)),
        _ => None,
    })
}

fn evict_one_unmapped(data: &TmpfsFileData) -> bool {
    let Some((idx, pa, cgid)) = candidate(data) else { return false; };
    evict_unmapped(data, idx, pa, cgid)
}

fn evict_unmapped(data: &TmpfsFileData, idx: u64, pa: u64, cgid: u64) -> bool {
    let Ok(Some(isolated)) = pmm::setup::isolate_anon_lru_pfn(pa) else { return false; };
    if !pmm::setup::try_lock_page(pa) {
        let _ = pmm::setup::putback_isolated_lru(isolated);
        return false;
    }
    // The inode lock serializes shared-frame handoff. A concurrent mapper's
    // `inc_ref` increments mapcount before it can observe this page, so the
    // second check closes the isolate-to-store race without PTE surgery.
    let bytes = {
        let pages = data.pages.lock();
        match pages.get(&idx).copied() {
            Some(ShmemPage::Resident { pa: current, cgid: owner })
                if current == pa && owner == cgid && pmm::setup::frame_mapcount(pa) == 0 => {
                let Some(base) = pmm::setup::frame_ptr(pa) else {
                    let _ = pmm::setup::putback_isolated_lru(isolated);
                    let _ = pmm::setup::unlock_page(pa);
                    return false;
                };
                // SAFETY: page lock excludes writer/reclaim mutation and the
                // unmapped object page cannot be changed through a user PTE.
                unsafe { core::slice::from_raw_parts(base, hal::PAGE_SIZE_BYTES as usize) }.to_vec()
            }
            _ => {
                let _ = pmm::setup::putback_isolated_lru(isolated);
                let _ = pmm::setup::unlock_page(pa);
                return false;
            }
        }
    };
    if !cgroup::try_charge_swap(cgid, hal::PAGE_SIZE_BYTES) {
        let _ = pmm::setup::putback_isolated_lru(isolated);
        let _ = pmm::setup::unlock_page(pa);
        return false;
    }
    let entry = match store_page(&bytes, cgid) {
        Some(entry) => entry,
        None => {
            cgroup::uncharge_swap(cgid, hal::PAGE_SIZE_BYTES);
            let _ = pmm::setup::putback_isolated_lru(isolated);
            let _ = pmm::setup::unlock_page(pa);
            return false;
        }
    };
    let committed = {
        let mut pages = data.pages.lock();
        match pages.get(&idx).copied() {
            Some(ShmemPage::Resident { pa: current, cgid: owner })
                if current == pa && owner == cgid && pmm::setup::frame_mapcount(pa) == 0 => {
                pages.insert(idx, ShmemPage::Swapped { entry, cgid });
                true
            }
            _ => false,
        }
    };
    if !committed {
        let _ = pmm::swap::free_page(entry);
        let _ = pmm::setup::putback_isolated_lru(isolated);
        let _ = pmm::setup::unlock_page(pa);
        return false;
    }
    vfs::memory_accounting::account_shmem_remove(1);
    cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, hal::PAGE_SIZE_BYTES);
    pmm::kassert!(pmm::setup::release_isolated_lru(isolated).is_ok(), "tmpfs reclaim lru release invariant");
    let _ = pmm::setup::unlock_page(pa);
    // SAFETY: the inode's sole object hold was atomically replaced by `entry`.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
    true
}

fn evict_one_mapped(data: &TmpfsFileData) -> bool {
    let candidate = data.pages.lock().iter().find_map(|(&idx, page)| match *page {
        ShmemPage::Resident { pa, cgid } if pmm::setup::frame_mapcount(pa) != 0 => Some((idx, pa, cgid)), _ => None,
    });
    let Some((idx, pa, cgid)) = candidate else { return false; };
    evict_mapped(data, idx, pa, cgid)
}

fn evict_mapped(data: &TmpfsFileData, idx: u64, pa: u64, cgid: u64) -> bool {
    let Ok(Some(isolated)) = pmm::setup::isolate_anon_lru_pfn(pa) else { return false; };
    if !pmm::setup::try_lock_page(pa) { let _ = pmm::setup::putback_isolated_lru(isolated); return false; }
    let Some((token, frozen)) = freeze_mapped_page(data, idx, pa, cgid) else {
        let _ = pmm::setup::putback_isolated_lru(isolated); let _ = pmm::setup::unlock_page(pa); return false;
    };
    let Some(base) = pmm::setup::frame_ptr(pa) else { rollback_frozen_page(data, idx, pa, cgid, token, frozen); let _ = pmm::setup::putback_isolated_lru(isolated); let _ = pmm::setup::unlock_page(pa); return false; };
    let bytes = unsafe { core::slice::from_raw_parts(base, hal::PAGE_SIZE_BYTES as usize) }.to_vec();
    if !cgroup::try_charge_swap(cgid, hal::PAGE_SIZE_BYTES) { rollback_frozen_page(data, idx, pa, cgid, token, frozen); let _ = pmm::setup::putback_isolated_lru(isolated); let _ = pmm::setup::unlock_page(pa); return false; }
    let entry = match store_page(&bytes, cgid) { Some(e) => e, None => { cgroup::uncharge_swap(cgid, hal::PAGE_SIZE_BYTES); rollback_frozen_page(data, idx, pa, cgid, token, frozen); let _ = pmm::setup::putback_isolated_lru(isolated); let _ = pmm::setup::unlock_page(pa); return false; } };
    // `store_page` creates the inode-index reference.  Reserve one further
    // reference for every frozen PTE before changing a single marker: retain
    // failure must leave the whole page recoverable through rollback.
    let mut retained = 0usize;
    for _ in &frozen {
        if pmm::swap::retain_page(entry).is_err() {
            for _ in 0..retained { let _ = pmm::swap::free_page(entry); }
            let _ = pmm::swap::free_page(entry);
            rollback_frozen_page(data, idx, pa, cgid, token, frozen);
            let _ = pmm::setup::putback_isolated_lru(isolated);
            let _ = pmm::setup::unlock_page(pa);
            return false;
        }
        retained += 1;
    }
    if retained == 0 {
        let _ = pmm::swap::free_page(entry);
        rollback_frozen_page(data, idx, pa, cgid, token, frozen);
        let _ = pmm::setup::putback_isolated_lru(isolated);
        let _ = pmm::setup::unlock_page(pa);
        return false;
    }
    for pte in &frozen {
        let _pt = pte.mm.lock_page_table();
        #[cfg(target_arch = "x86_64")]
        let changed = unsafe { hal::pt_walker::replace_migration_4k_with_swap_at_root::<hal_x86_64::vmm::PtWalkerX86>(pte.mm.root_pa(), pte.va, token, entry, hhdm_offset()) };
        #[cfg(target_arch = "aarch64")]
        let changed = unsafe { hal::pt_walker::replace_migration_4k_with_swap_at_root::<hal_aarch64::vmm::PtWalkerArm>(pte.mm.root_pa(), pte.va, token, entry, hhdm_offset()) };
        drop(_pt);
        if changed {
            flush_mapping(&pte.mm, pte.va);
            pte.mm.account_present_to_swap_at(hal::UserVirtAddr::new(pte.va).unwrap());
            if let Some(source) = vmm::migration_drop_marker_mapping(token) {
                // SAFETY: this exact marker consumed one resident PTE ref;
                // the inode object ref remains until index publication.
                unsafe { pmm::setup::rmap_aware_dec_and_maybe_free(source); }
            }
        } else {
            // A concurrent munmap/teardown owns its physical PTE release.
            // Drop only the slot ref reserved for this now-absent marker.
            let _ = pmm::swap::free_page(entry);
        }
    }
    let published = {
        let mut pages = data.pages.lock();
        if matches!(pages.get(&idx), Some(ShmemPage::Migrating { pa: current, cgid: owner, token: current_token })
            if *current == pa && *owner == cgid && *current_token == token) {
            pages.insert(idx, ShmemPage::Swapped { entry, cgid });
            #[cfg(feature = "debug-zram-lifecycle")]
            super::lifetime::trace_migration(b"commit", data, idx, token);
            true
        } else { false }
    };
    pmm::kassert!(published, "tmpfs mapped migration index terminal invariant");
    let _ = vmm::migration_finish(token);
    #[cfg(target_os = "oxide-kernel")]
    sched::live::migration_wait::wake(token.token());
    vfs::memory_accounting::account_shmem_remove(1);
    cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, hal::PAGE_SIZE_BYTES);
    pmm::kassert!(pmm::setup::release_isolated_lru(isolated).is_ok(), "tmpfs mapped reclaim lru release invariant");
    let _ = pmm::setup::unlock_page(pa);
    // SAFETY: the inode object hold is replaced by the swap-index ref only
    // after every original PTE ref was transferred or removed.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
    true
}

/// Page out exactly the complete tmpfs pages intersecting `[off, off+len)`.
/// This is the MAP_SHARED `MADV_PAGEOUT` entry: unlike the shrinker it never
/// selects a different inode page than the caller requested. # C: O(pages)
pub(super) fn pageout_range(data: &TmpfsFileData, off: u64, len: u64) -> KResult<usize> {
    if len == 0 { return Ok(0); }
    let indices = page_indices(off, len)?;
    let mut released = 0usize;
    for idx in indices {
        let page = data.pages.lock().get(&idx).copied();
        let Some(ShmemPage::Resident { pa, cgid }) = page else { continue; };
        let reclaimed = if pmm::setup::frame_mapcount(pa) == 0 {
            evict_unmapped(data, idx, pa, cgid)
        } else {
            evict_mapped(data, idx, pa, cgid)
        };
        if reclaimed { released += 1; }
    }
    Ok(released)
}

/// Complete inode page indices intersecting the caller's byte range.
/// Kept separate so the exact routing contract is host-testable without a
/// live PMM/swap device. # C: O(1)
fn page_indices(off: u64, len: u64) -> KResult<core::ops::RangeInclusive<u64>> {
    let end = off.checked_add(len).ok_or(VfsError::Einval)?;
    let first = off / hal::PAGE_SIZE_BYTES;
    let last = end.saturating_sub(1) / hal::PAGE_SIZE_BYTES;
    Ok(first..=last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn pageout_range_selects_only_intersecting_inode_indices() {
        let page = hal::PAGE_SIZE_BYTES;
        let selected: Vec<u64> = page_indices(page + 17, page - 18).unwrap().collect();
        assert_eq!(selected, vec![1], "a one-page request must not reclaim neighbours");
        let crossing: Vec<u64> = page_indices(page - 1, 2).unwrap().collect();
        assert_eq!(crossing, vec![0, 1]);
    }
}
