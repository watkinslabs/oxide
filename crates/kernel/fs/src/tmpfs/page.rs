// Backing-frame resolution for one shmem page index. Allocation and swap I/O
// are sleepable, so neither may run under the inode's page-index spinlock.

use vfs::{KResult, VfsError};

use super::file::{ShmemPage, TmpfsFileData};
use super::limits::PG;

/// Resolve the allocating task's memcg once at the page-allocation boundary.
/// # C: O(log n)
fn allocating_memcg() -> u64 {
    sched::current().map(|t| cgroup::cgroup_of(t.tid as u64))
        .unwrap_or_else(cgroup::kernel_context_memcg)
}

fn release_frame(pa: u64, cgid: u64) {
    // SAFETY: the losing/private frame has no page-index or PTE reference.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
    cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
}

fn alloc_frame(cgid: u64) -> KResult<u64> {
    if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64) {
        return Err(VfsError::Enomem);
    }
    let Some(pa) = pmm::setup::alloc_object_frame() else {
        cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
        return Err(VfsError::Enomem);
    };
    let Some(ptr) = pmm::setup::frame_ptr(pa) else {
        release_frame(pa, cgid);
        return Err(VfsError::Enomem);
    };
    // SAFETY: ptr spans the fresh unpublished frame.
    hal::zerotrap::trap(ptr as *const u8, PG);
    // SAFETY: ptr spans the fresh unpublished frame.
    unsafe { core::ptr::write_bytes(ptr, 0, PG); }
    Ok(pa)
}

fn admit_frame(pa: u64, cgid: u64) -> KResult<()> {
    pmm::setup::classify_shmem_page(pa, cgid);
    if pmm::setup::admit_shmem_lru(pa).is_err() { return Err(VfsError::Eio); }
    Ok(())
}

fn publish_new(f: &TmpfsFileData, idx: u64) -> KResult<()> {
    f.acct_one_block()?;
    let cgid = allocating_memcg();
    let pa = match alloc_frame(cgid) {
        Ok(pa) => pa,
        Err(error) => { f.unacct_one_block(); return Err(error); }
    };
    if let Err(error) = admit_frame(pa, cgid) {
        release_frame(pa, cgid);
        f.unacct_one_block();
        return Err(error);
    }
    let won = {
        let mut pages = f.pages.lock();
        if pages.contains_key(&idx) { false }
        else {
            pages.insert(idx, ShmemPage::Resident { pa, cgid });
            true
        }
    };
    if won {
        vfs::memory_accounting::account_shmem_publish(1);
    } else {
        release_frame(pa, cgid);
        f.unacct_one_block();
    }
    Ok(())
}

fn publish_swapin(f: &TmpfsFileData, idx: u64, entry: hal::pt_walker::SwapEntry,
                  cgid: u64, shadow: u64) -> KResult<()> {
    // The extra slot reference pins the bytes while truncate or another
    // swap-in races the unlocked I/O below.
    let pa = match alloc_frame(cgid) {
        Ok(pa) => pa,
        Err(error) => { let _ = pmm::swap::free_page(entry); return Err(error); }
    };
    let result = (|| {
        let ptr = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
        // SAFETY: pa is private and ptr spans its complete page.
        let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, PG) };
        pmm::swap::load_page(entry, bytes).map_err(|_| VfsError::Eio)?;
        admit_frame(pa, cgid)
    })();
    if let Err(error) = result {
        release_frame(pa, cgid);
        let _ = pmm::swap::free_page(entry);
        return Err(error);
    }
    let won = {
        let mut pages = f.pages.lock();
        match pages.get(&idx).copied() {
            Some(ShmemPage::Swapped { entry: current, cgid: owner, shadow: age })
                if current == entry && owner == cgid && age == shadow => {
                    pages.insert(idx, ShmemPage::Resident { pa, cgid });
                    true
                }
            _ => false,
        }
    };
    if won {
        vfs::memory_accounting::account_shmem_publish(1);
        // Drop the page-index's old reference, then this I/O pin.
        let _ = pmm::swap::free_page(entry);
        let _ = pmm::swap::free_page(entry);
    } else {
        release_frame(pa, cgid);
        let _ = pmm::swap::free_page(entry);
    }
    Ok(())
}

enum Work {
    Wait(hal::pt_walker::MigrationEntry),
    Swap { entry: hal::pt_walker::SwapEntry, cgid: u64, shadow: u64 },
    Allocate,
}

fn resolve_work(f: &TmpfsFileData, idx: u64, work: Work) -> KResult<()> {
    match work {
        Work::Wait(token) => super::migration::wait_and_restart(token),
        Work::Swap { entry, cgid, shadow } => publish_swapin(f, idx, entry, cgid, shadow)?,
        Work::Allocate => publish_new(f, idx)?,
    }
    Ok(())
}

fn with_resident_by<R>(f: &TmpfsFileData, idx: u64, create: bool,
                       mut resolve: impl FnMut(&TmpfsFileData, u64, Work) -> KResult<()>,
                       mut use_page: impl FnMut(u64) -> KResult<R>) -> KResult<Option<R>> {
    loop {
        let work = {
            let pages = f.pages.lock();
            match pages.get(&idx).copied() {
                Some(ShmemPage::Resident { pa, .. }) => return use_page(pa).map(Some),
                Some(ShmemPage::Migrating { token, .. }) => Work::Wait(token),
                Some(ShmemPage::Swapped { entry, cgid, shadow }) => {
                    // Pin under the index lock so truncate cannot release and
                    // reuse the slot between lookup and unlocked I/O.
                    pmm::swap::retain_page(entry).map_err(|_| VfsError::Eio)?;
                    Work::Swap { entry, cgid, shadow }
                }
                None if !create => return Ok(None),
                None => Work::Allocate,
            }
        };
        resolve(f, idx, work)?;
    }
}

/// Run `use_page` while the page-index lock keeps its resident frame stable.
/// Allocation and swap-in happen without that spinlock and compare-publish on
/// re-entry; a racing winner is reused. A read-only hole returns `None`.
/// # C: O(page I/O + log N_pages)
pub(super) fn with_resident<R>(f: &TmpfsFileData, idx: u64, create: bool,
                               use_page: impl FnMut(u64) -> KResult<R>) -> KResult<Option<R>> {
    with_resident_by(f, idx, create, resolve_work, use_page)
}

#[cfg(test)]
pub(super) fn unlocked_resolution_reuses_winner_for_test(f: &TmpfsFileData, idx: u64,
                                                         winner: u64) -> bool {
    let mut unlocked = false;
    let result = with_resident_by(f, idx, true, |file, page_idx, work| {
        unlocked = file.pages.try_lock().is_some();
        if !matches!(work, Work::Allocate) { return Err(VfsError::Eio); }
        file.pages.lock().insert(page_idx, ShmemPage::Resident { pa: winner, cgid: 0 });
        Ok(())
    }, Ok);
    unlocked && result == Ok(Some(winner))
}
