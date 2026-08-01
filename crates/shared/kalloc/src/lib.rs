// Kernel heap allocator (`kalloc`).
//
// `KAlloc` is a `GlobalAlloc` implementation backed by a sorted hole-list
// (`holes::HoleList`) with a `Spinlock<HoleList, KMalloc>` guard. The
// `KMalloc` lock class is the leaf of the partial order (`06§3.6`); any
// other subsystem may hold its own lock and call into kalloc, but kalloc
// never calls back into them.
//
// Boot sets up a single fixed-size BSS heap (`STATIC_HEAP_SIZE`) and
// hands its byte range to `KAlloc::init`. Future revisions per `12§2`
// will replace the static heap with PMM-backed slab size-class routing
// once a kernel binary stage exists; the public `GlobalAlloc` surface
// stays.
//
// Hosted tests instantiate fresh `KAlloc` instances over their own
// `Vec<u8>` buffers — no global state.
//
// Module manifest (`docs/08§7`):
//   limits       heap sizes, growth granularity, diagnostic cadences
//   static_heap  the BSS boot heap `init_static` hands to `init`
//   state        `AllocState`, the `KAlloc` handle, init + hook installation, `IrqOff`
//   context      memcg allocation domains and their RAII scopes
//   galloc       the `GlobalAlloc` alloc/dealloc dispatch
//   grow         PMM growth path + `kmalloc` slab refill/drain
//   holes        sorted hole list (the free-list data structure)
//   sizeclass    `kmalloc` per-size LIFO front end
//   caller       return-IP capture for allocation provenance
//   hooks        kernel-installed diagnostic callbacks + `[KALLOC]` seq counter
//   validate     tight/periodic free-list integrity checking
//   uaf          use-after-free / evicted-block provenance queries
//   recent       recent-op ring dumped at a detection or fault
//   watchpoint   `debug-hw-watchpoint` freed-block write watchpoint
//   efence       `debug-efence` guard-arena routing hooks
//   poison       `debug-heappoison` quarantine + redzones
//   size_track   `debug-dealloc-diag` live-allocation size ledger
//   walkstat     `debug-heapwalk` hole-list walk-step counters

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
#[cfg(any(test, feature = "hosted"))]
extern crate std;

mod context;
mod galloc;
mod grow;
mod holes;
mod hooks;
mod limits;
mod recent;
mod sizeclass;
mod state;
mod static_heap;
mod uaf;
mod validate;
#[cfg(feature = "debug-heapwalk")] pub mod walkstat;
#[cfg(feature = "debug-dealloc-diag")] mod size_track;
#[cfg(feature = "debug-heappoison")] mod poison;
#[cfg(feature = "debug-efence")] mod efence;
#[cfg(feature = "debug-hw-watchpoint")] mod watchpoint;
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag", feature = "debug-efence"))]
mod caller;

pub use holes::{HoleList, HoleListError, MIN_HOLE_ALIGN, MIN_HOLE_SIZE};
pub use limits::{GROW_CHUNK_MIN, MIB, NO_MEMCG_CONTEXT, STATIC_HEAP_SIZE, UAF_FREE_IP_UNKNOWN};
pub use state::KAlloc;
pub use context::{enter_global_context, replace_global_context, AllocationContext, AllocationScope, GlobalAllocationScope};
pub use grow::GrowFn;
pub use recent::dump_corruption_diag;
pub use uaf::{evicted_lookup, uaf_lookup};
pub use validate::{arm_tight_validate, checkpoint};
#[cfg(feature = "debug-heappoison")] pub use uaf::validate_global;
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub use hooks::{set_corruption_probe_hook, set_current_ctx_hook, set_irq_info_hook, CorruptionProbeFn};
#[cfg(feature = "debug-hw-watchpoint")]
pub use watchpoint::{set_watchpoint_disarm_hook, set_watchpoint_hook, WatchpointArmFn, WatchpointDisarmFn};
#[cfg(feature = "debug-efence")] pub use efence::install_efence;

#[cfg(test)]
mod tests;
