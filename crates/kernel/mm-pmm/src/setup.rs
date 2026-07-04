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
#[cfg(feature = "debug-cow")]
mod alloc_integrity;
#[cfg(test)]
mod tests;

pub use boot_init::{HhdmBacking, MAX_REGIONS, SetupError, init_from_boot_info, pmm_static};
pub use frame_alloc::{alloc_one_frame, alloc_object_frame, alloc_raw_frame, frame_ptr};
pub use refs::{can_reuse_anon_exclusive, dec_and_maybe_free_frame, dec_object_ref_and_maybe_free_frame, frame_refcount, inc_ref};
pub use metadata::{anon_vma_for_pa, clear_anon_rmap_for_pa, init_page_meta, page_index_for_pa, pfn_max_from_boot_info, rmap_aware_dec_and_maybe_free, set_anon_rmap_for_pa};
#[cfg(feature = "debug-fwm")]
pub use metadata::fwm_peer_maps;
#[cfg(feature = "debug-atexit")]
pub use metadata::set_dec_ctx;
pub(crate) use metadata::page_meta;
pub use contig::{alloc_contig, alloc_contig_object, free_contig, free_one_frame};
