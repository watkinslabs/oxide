//! `/proc/vmstat` from implemented VM owner counters.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl core::fmt::Write for VecFmt<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

fn body() -> Vec<u8> {
    let s = crate::memory::snapshot();
    let anon = s.anon_pages().saturating_sub(s.shmem_pages);
    let file = s.file_cache_pages.saturating_add(s.shmem_pages);
    let mut out = Vec::with_capacity(640);
    for &(key, value) in &[
        ("nr_free_pages", s.free_pages),
        ("nr_zone_inactive_anon", s.inactive_anon),
        ("nr_zone_active_anon", s.active_anon),
        ("nr_zone_inactive_file", s.inactive_file),
        ("nr_zone_active_file", s.active_file),
        ("nr_zone_unevictable", s.unevictable),
        ("nr_zone_write_pending", s.writeback_file_pages),
        ("nr_page_table_pages", s.page_table_pages),
        ("nr_kernel_stack", s.kernel_stack_bytes / hal::PAGE_SIZE_BYTES),
        ("nr_inactive_anon", s.inactive_anon),
        ("nr_active_anon", s.active_anon),
        ("nr_inactive_file", s.inactive_file),
        ("nr_active_file", s.active_file),
        ("nr_unevictable", s.unevictable),
        ("nr_slab_reclaimable", s.slab_reclaimable_pages),
        ("nr_slab_unreclaimable", s.slab_unreclaimable_pages),
        ("nr_anon_pages", anon),
        ("nr_mapped", s.anon_pte_mappings.saturating_add(s.file_pte_mappings)),
        ("nr_file_pages", file),
        ("nr_dirty", s.dirty_file_pages),
        ("nr_writeback", s.writeback_file_pages),
        ("nr_shmem", s.shmem_pages),
        ("pgalloc_normal", s.pmm_alloc_events),
        ("pgfree", s.pmm_free_events),
        ("pgactivate", s.reclaim_activated),
        ("pgdeactivate", s.reclaim_deactivated),
        ("pgfault", s.faults),
        ("pgscan_kswapd", s.reclaim_scanned),
        ("pgsteal_kswapd", s.reclaim_stolen),
    ] {
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!("{key} {value}\n"));
    }
    out
}

/// `/proc/vmstat` inode. # C: O(1)
pub fn make_proc_vmstat() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::VMSTAT as Ino, body) }
