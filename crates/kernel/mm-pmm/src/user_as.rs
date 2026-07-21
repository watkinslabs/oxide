// User address-space module manifest.
//
// `state` owns global AS/HHDM state and CPU/mm cpumask helpers.
// `foreign` owns foreign-root copy helpers, PTE permission rewrites, rmap walks.
// `teardown` owns AS page-table teardown and fault classification helpers.
// `debug` owns cfg-gated fault diagnostics and debug watch hooks.
// `fault` owns arch fault dispatch and demand-page resolution.
// `mmap` owns mmap syscall glue.
// `unmap` owns madvise/munmap page eviction glue.
// `diag` owns stack prefault and file-page diagnostic helpers.
// `signal` owns SIGSEGV delivery.
// `swap_in` owns the one authoritative swap-PTE-to-RAM restoration path.
// `swapoff` owns live-area drain orchestration across all address spaces.
// `accounting` owns PTE-derived resident/swap observation for procfs.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use alloc::sync::Arc;

use vmm::{AddressSpace, FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};
use hal::{UserVirtAddr, USER_VA_END};

mod signal;
mod accounting;
mod swap_in;
mod swapoff;
pub(crate) mod pageout;
mod state;
mod foreign;
mod teardown;
#[cfg(any(feature = "debug-cow", feature = "debug-displaystack", all(feature = "debug-mount", target_arch = "x86_64")))]
mod debug;
mod fault;
mod mmap;
mod unmap;
mod diag;

pub use signal::{CoredumpFn, set_coredump_hook};
pub use accounting::{oom_memory, range_memory_stats, RangeMemoryStats};
#[cfg(target_arch = "x86_64")]
pub use signal::deliver_sigsegv_x86;
#[cfg(target_arch = "aarch64")]
pub use signal::deliver_sigsegv_arm;
#[cfg(target_arch = "x86_64")]
use signal::try_deliver_sigsegv_via_handler_x86;

use state::{current_cpu_idx, current_mm_cpumask, HHDM_OFFSET};
pub use state::{clone_global_arc, hhdm_offset, init, with};
pub use foreign::{evict_foreign_pages_in_range, mprotect_pages, read_foreign_user, rmap_walk_anon_pa, write_foreign_user};
use foreign::{read_foreign_leaf, read_foreign_leaf_pa};
#[cfg(target_arch = "x86_64")]
pub use teardown::classify_x86_pf;
#[cfg(target_arch = "aarch64")]
pub use teardown::classify_arm_abort;
pub use teardown::{as_teardown, install_teardown, prot_from_linux};
#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
pub use debug::{install_lock_step_hook, lock_step_hook};
#[cfg(feature = "debug-cow")]
use debug::segv_dump;
#[cfg(feature = "debug-displaystack")]
use debug::dump_arm_vmas;
pub use fault::user_fault_handler;
pub use swapoff::drain_swap_area;
pub use swap_in::restore_swap_for_fork;
pub use mmap::glue_mmap;
pub use mmap::populate_current_range;
pub use pageout::{flush_reclaim_mapping, pageout_anon_range};
pub use crate::munmap_range::validate_munmap_range;
pub use unmap::{evict_pages_in_range, glue_munmap};
#[cfg(target_arch = "x86_64")]
pub use diag::{diag_verify_file_pages, prefault_stack};
