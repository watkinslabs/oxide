// PMM setup module manifest.
//
// `boot_init` owns BootInfo memmap ingestion, HHDM backing, static PMM storage.
// `frame_alloc` owns single-frame allocation entry points and alloc-time checks.
// `refs` owns PageMeta refcount/mapcount transitions.
// `metadata` owns PageMeta installation, anon-rmap metadata, debug attribution.
// `contig` owns contiguous allocation and final frame free paths.
// `alloc_integrity` owns debug-cow shadow allocation tracking.
// `tests` owns setup unit tests.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use hal::{Pfn, PAGE_SHIFT, PAGE_SIZE_BYTES};
use crate::{Error as PmmError, PageBacking, Pmm, UsableRegion, ORDERS};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};

mod boot_init;
mod frame_alloc;
mod refs;
mod metadata;
mod contig;
mod page_tables;
mod percpu;
#[cfg(feature = "debug-cow")]
#[cfg(feature = "debug-cow")]
mod alloc_integrity;
#[cfg(test)]
mod tests;

pub use boot_init::{HhdmBacking, MAX_REGIONS, SetupError, init_from_boot_info, pmm_static};
pub use frame_alloc::{alloc_one_frame, alloc_object_frame, alloc_movable_object_frame, alloc_raw_frame, frame_ptr, migrate_movable_object_frame, release_movable_object_frame, release_object_frame};
pub use refs::{can_reuse_anon_exclusive, dec_and_maybe_free_frame, dec_object_ref_and_maybe_free_frame, frame_refcount, inc_object_ref, inc_ref};
pub use metadata::{admit_anon_lru, admit_file_lru, admit_shmem_lru, anon_vma_for_pa, classify_file_page, classify_shmem_page, clear_anon_exclusive, clear_anon_rmap_for_pa, clear_file_rmap_for_pa, file_rmap_for_pa, frame_mapcount, init_page_meta, isolate_anon_lru_pfn, isolate_inactive_anon_lru, isolate_inactive_anon_lru_memcg, isolate_inactive_file_lru, mark_lru_referenced, memcg_for_pa, page_index_for_pa, pfn_max_from_boot_info, putback_isolated_lru, reclaim_snapshot, release_isolated_lru, rmap_aware_dec_and_maybe_free, set_anon_rmap_for_pa, set_file_rmap_for_pa, set_lru_unevictable, set_memcg_for_pa, try_lock_page, unlink_lru_for_final_free, unlock_page};
// free-while-mapped peer-scan repair: opt-in DIAG only. The always-on
// never-free-a-mapped-page invariant lives in `refs::release_frame_on_zero`
// (cheap own-mapcount check); the expensive cross-AS page-table scan below is
// a `debug-fwm` backstop for an under-count, not a production hot path.
#[cfg(feature = "debug-fwm")]
pub use refs::repair_frame_counts;
#[cfg(feature = "debug-fwm")]
pub use metadata::fwm_peer_maps;
#[cfg(feature = "debug-atexit")]
pub use metadata::set_dec_ctx;
pub(crate) use metadata::page_meta;
pub use contig::{alloc_contig, alloc_contig_object, free_contig, free_one_frame};
pub use page_tables::{alloc_page_table_frame, page_table_snapshot, PageTableSnapshot};
pub use percpu::{alloc_percpu_page, percpu_snapshot, PerCpuSnapshot};
pub use crate::watermark::{allocation_policy, watermark_snapshot, AllocationPolicy, WatermarkSnapshot};
#[cfg(target_os = "oxide-kernel")]
pub use crate::kswapd::spawn_kswapd;
