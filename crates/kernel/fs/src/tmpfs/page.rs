// Backing-frame allocation for one shmem page index: first touch, refault from
// swap, and the block accounting a new page costs.
//
// A first-touch page is charged BEFORE it is allocated — the mount's block
// ceiling then the owning inode's block quota — so a refusal never leaves a
// frame behind, and an owner over quota is told so at allocation rather than
// after the bytes are already in memory. A refault charges nothing: the page
// was charged when it was first allocated and has kept its charge across the
// swap-out.

use alloc::collections::BTreeMap;

use vfs::{KResult, VfsError};

use super::file::{ShmemPage, TmpfsFileData};
use super::limits::PG;

/// Resolve the allocating task's memcg once, at the shmem page-allocation
/// boundary.  A pre-scheduler kernel context is charged to the root memcg,
/// matching Linux's root allocation context rather than inventing an owner
/// later during reclaim or teardown. # C: O(log n)
fn allocating_memcg() -> u64 {
    sched::current().map(|t| cgroup::cgroup_of(t.tid as u64)).unwrap_or_else(cgroup::kernel_context_memcg)
}

/// Frame for `idx`, allocating + zeroing on first touch and charging one block
/// against the mount's accounting (`ENOSPC` at the mount ceiling, `EDQUOT` at
/// the owner's) . The frame holds the inode's single object reference
/// (refcount 1, mapcount 0). # C: O(log N_pages)
pub(super) fn ensure_page(g: &mut BTreeMap<u64, ShmemPage>, idx: u64, f: &TmpfsFileData) -> KResult<u64> {
    if let Some(page) = g.get(&idx).copied() {
        if let Some(pa) = page.resident_pa() { return Ok(pa); }
        let ShmemPage::Swapped { entry, cgid, .. } = page else { return Err(VfsError::Eagain); };
        // A swapped shmem page retains its inode index and swap charge.  A
        // refault allocates a new object frame, restores bytes, and only then
        // consumes the old swap entry; failed reload leaves the index intact.
        if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64) {
            return Err(VfsError::Enomem);
        }
        let Some(pa) = pmm::setup::alloc_object_frame() else {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Enomem);
        };
        let Some(ptr) = pmm::setup::frame_ptr(pa) else {
            // SAFETY: this unpublished object frame has only its allocation ref.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Enomem);
        };
        // SAFETY: `ptr` spans the newly allocated page and no PTE can name it.
        let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, PG) };
        if pmm::swap::load_page(entry, bytes).is_err() {
            // SAFETY: failed I/O left the frame private to this construction.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Eio);
        }
        pmm::setup::classify_shmem_page(pa, cgid);
        if pmm::setup::admit_shmem_lru(pa).is_err() {
            // The old swap entry remains authoritative until this admission is
            // complete; don't publish a resident page outside reclaim state.
            // SAFETY: no PTE owns this failed refault frame.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Eio);
        }
        g.insert(idx, ShmemPage::Resident { pa, cgid });
        vfs::memory_accounting::account_shmem_publish(1);
        // Data is present in the new page-index entry before the swap slot is
        // released. `free_page` also removes the matching swap memcg charge.
        let _ = pmm::swap::free_page(entry);
        return Ok(pa);
    }
    f.acct_one_block()?;
    let cgid = allocating_memcg();
    if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64) {
        f.unacct_one_block();
        return Err(VfsError::Enomem);
    }
    let pa = match pmm::setup::alloc_object_frame() {
        Some(p) => p,
        None => {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            f.unacct_one_block();
            return Err(VfsError::Enomem);
        }
    };
    let ptr = match pmm::setup::frame_ptr(pa) {
        Some(p) => p,
        None => {
            // SAFETY: allocation published no page-index entry, so this is the
            // sole object reference and the failed construction rolls back fully.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            f.unacct_one_block();
            return Err(VfsError::Enomem);
        }
    };
    // SAFETY: pa is a freshly-allocated PMM frame; PG is the page granule.
    hal::zerotrap::trap((ptr) as *const u8, (PG) as usize);
    // SAFETY: ptr names the full freshly-allocated frame, and PG is its size.
    unsafe { core::ptr::write_bytes(ptr, 0, PG); }
    pmm::setup::classify_shmem_page(pa, cgid);
    pmm::kassert!(pmm::setup::admit_shmem_lru(pa).is_ok(), "shmem lru admission invariant");
    g.insert(idx, ShmemPage::Resident { pa, cgid });
    vfs::memory_accounting::account_shmem_publish(1);
    Ok(pa)
}
