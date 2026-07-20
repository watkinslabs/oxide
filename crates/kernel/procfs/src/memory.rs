//! Cross-owner VM observation used by procfs and sysinfo.
//!
//! Every input remains owned by the subsystem that changes it.  This module
//! takes one read-only aggregate so ABI renderers cannot independently invent
//! memory classifications.

use slab::registry::CacheFlags;

/// One coherent, read-only observation of currently implemented VM owners.
/// Units are base pages except byte fields explicitly named `*_bytes`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub managed_pages: u64,
    pub free_pages: u64,
    pub inactive_anon: u64,
    pub active_anon: u64,
    pub inactive_file: u64,
    pub active_file: u64,
    pub unevictable: u64,
    pub file_cache_pages: u64,
    pub dirty_file_pages: u64,
    pub writeback_file_pages: u64,
    pub shmem_pages: u64,
    pub page_table_pages: u64,
    pub percpu_pages: u64,
    pub slab_reclaimable_pages: u64,
    pub slab_unreclaimable_pages: u64,
    pub slab_idle_reclaimable_pages: u64,
    pub kernel_stack_bytes: u64,
    pub vmalloc_total_bytes: u64,
    pub vmalloc_used_bytes: u64,
    pub vmalloc_largest_free_bytes: u64,
    pub committed_virtual_bytes: u64,
    pub locked_virtual_bytes: u64,
    pub anon_pte_mappings: u64,
    pub file_pte_mappings: u64,
    pub swap_pte_mappings: u64,
    pub faults: u64,
    pub pmm_alloc_events: u64,
    pub pmm_free_events: u64,
    pub reclaim_scanned: u64,
    pub reclaim_stolen: u64,
    pub reclaim_activated: u64,
    pub reclaim_deactivated: u64,
    pub swap_total_pages: u64,
    pub swap_free_pages: u64,
}

impl Snapshot {
    /// Physical pages currently resident on anon/shmem LRUs. # C: O(1)
    pub fn anon_pages(self) -> u64 {
        self.inactive_anon.saturating_add(self.active_anon)
    }

    /// Physical pages currently resident on file LRUs. # C: O(1)
    pub fn file_lru_pages(self) -> u64 {
        self.inactive_file.saturating_add(self.active_file)
    }

    /// Reclaimable clean page-cache pages. # C: O(1)
    pub fn clean_file_cache_pages(self) -> u64 {
        self.file_cache_pages.saturating_sub(self.dirty_file_pages)
            .saturating_sub(self.writeback_file_pages)
    }

    /// Conservative, source-backed `MemAvailable` input. # C: O(1)
    pub fn available_pages(self) -> u64 {
        self.free_pages.saturating_add(self.clean_file_cache_pages())
            .saturating_add(self.slab_idle_reclaimable_pages)
            .min(self.managed_pages)
    }
}

/// Fold live owner snapshots once for all user-visible VM ABIs.  No input is
/// reconstructed from buddy allocation: PMM supplies capacity/free only;
/// every category comes from the owner that owns its lifecycle. # C: O(caches + swap areas + mms)
pub fn snapshot() -> Snapshot {
    let mut out = Snapshot::default();
    if let Some(pmm) = pmm::setup::pmm_static() {
        let p = pmm.snapshot();
        out.managed_pages = p.managed_pages;
        out.free_pages = p.free_pages;
        out.pmm_alloc_events = p.alloc_events;
        out.pmm_free_events = p.free_events;
    }
    if let Some(r) = pmm::setup::reclaim_snapshot() {
        out.inactive_anon = r.inactive_anon;
        out.active_anon = r.active_anon;
        out.inactive_file = r.inactive_file;
        out.active_file = r.active_file;
        out.unevictable = r.unevictable;
        out.reclaim_scanned = r.scanned;
        out.reclaim_stolen = r.stolen;
        out.reclaim_activated = r.activated;
        out.reclaim_deactivated = r.deactivated;
    }
    let pages = vfs::memory_page_snapshot();
    out.file_cache_pages = pages.file_cache_pages;
    out.dirty_file_pages = pages.dirty_file_pages;
    out.writeback_file_pages = pages.writeback_file_pages;
    out.shmem_pages = pages.shmem_pages;
    out.page_table_pages = pmm::setup::page_table_snapshot().frames;
    out.percpu_pages = pmm::setup::percpu_snapshot().pages;
    for cache in slab::registry::snapshots() {
        if cache.flags.contains(CacheFlags::RECLAIM_ACCOUNT) {
            out.slab_reclaimable_pages = out.slab_reclaimable_pages.saturating_add(cache.slab_pages as u64);
            out.slab_idle_reclaimable_pages = out.slab_idle_reclaimable_pages.saturating_add(cache.idle_pages as u64);
        } else {
            out.slab_unreclaimable_pages = out.slab_unreclaimable_pages.saturating_add(cache.slab_pages as u64);
        }
    }
    #[cfg(target_os = "oxide-kernel")]
    { out.kernel_stack_bytes = sched::kernel_stack_bytes_snapshot(); }
    let vmalloc = modules::linux_alloc::vmalloc_snapshot();
    out.vmalloc_total_bytes = vmalloc.total;
    out.vmalloc_used_bytes = vmalloc.used;
    out.vmalloc_largest_free_bytes = vmalloc.largest_free;
    let mm = vmm::global_accounting_snapshot();
    out.committed_virtual_bytes = mm.committed_virtual_bytes;
    out.locked_virtual_bytes = mm.locked_virtual_bytes;
    out.anon_pte_mappings = mm.anon_pte_mappings;
    out.file_pte_mappings = mm.file_pte_mappings;
    out.swap_pte_mappings = mm.swap_pte_mappings;
    out.faults = mm.faults;
    for area in pmm::swap::snapshot() {
        out.swap_total_pages = out.swap_total_pages.saturating_add(area.pages);
        out.swap_free_pages = out.swap_free_pages.saturating_add(area.pages.saturating_sub(area.used_pages));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::Snapshot;

    #[test]
    fn available_uses_only_releasable_owner_pages_and_never_exceeds_managed() {
        let s = Snapshot {
            managed_pages: 10,
            free_pages: 4,
            file_cache_pages: 5,
            dirty_file_pages: 2,
            writeback_file_pages: 1,
            slab_idle_reclaimable_pages: 3,
            ..Snapshot::default()
        };
        assert_eq!(s.clean_file_cache_pages(), 2);
        assert_eq!(s.available_pages(), 9);
        assert_eq!(Snapshot { managed_pages: 2, free_pages: 3, ..Snapshot::default() }.available_pages(), 2);
    }

    #[test]
    fn lru_and_file_helpers_keep_owner_classes_separate() {
        let s = Snapshot {
            inactive_anon: 2, active_anon: 3,
            inactive_file: 5, active_file: 7,
            ..Snapshot::default()
        };
        assert_eq!(s.anon_pages(), 5);
        assert_eq!(s.file_lru_pages(), 12);
    }

    #[test]
    fn vfs_shmem_owner_changes_the_aggregate_once() {
        let before = super::snapshot().shmem_pages;
        vfs::memory_accounting::account_shmem_publish(1);
        assert_eq!(super::snapshot().shmem_pages, before + 1);
        vfs::memory_accounting::account_shmem_remove(1);
        assert_eq!(super::snapshot().shmem_pages, before);
    }
}
