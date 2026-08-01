// Heap sizes, growth granularity and diagnostic cadences. Owned here per the
// constants-by-contract rule; the logic modules import, never redeclare.

/// Bytes in 1 MiB.
pub const MIB: usize = 1024 * 1024;

/// Heap size carved out of BSS for the kernel's static heap. 64 MiB
/// covers early-boot subsystems (vmm VMA tree, sched runqueues, vfs
/// dentry cache) BEFORE the PMM grow hook is wired (kmain); after that,
/// overflow routes to PMM-backed pages via `set_grow_hook` per `12§2`.
pub const STATIC_HEAP_SIZE: usize = 64 * MIB;

/// Minimum grow-callback request size — avoid thrashing the PMM with
/// tiny grows by always pulling a 1 MiB chunk.
pub const GROW_CHUNK_MIN: usize = 1 * MIB;

/// No explicit memcg allocation owner. Valid only for pre-init and
/// kernel-global domains; known owners must enter `AllocationContext`.
/// # C: O(1)
pub const NO_MEMCG_CONTEXT: u64 = 0;

/// No architectural free-site address is available for this diagnostic. # C: O(1)
pub const UAF_FREE_IP_UNKNOWN: u64 = 0;

/// Sentinel "no hook installed" stored in `KAlloc::grow_hook`.
pub(crate) const GROW_HOOK_NONE: u64 = 0;

/// Ops between periodic free-list validations (`debug-heappoison`). Small
/// enough to localize corruption to a tight window; large enough that the
/// O(N) walk isn't the hot path. Tightened from 64: two live corruption
/// captures this session were both caught lazily by `try_merge` instead of
/// by this periodic check, meaning the corruption happened within one
/// 64-op window of detection — narrower still means a real chance at
/// `last_op_ip` naming the actual corrupting call instead of an unrelated
/// later caller that merely stumbled into the already-trashed node.
#[cfg(feature = "debug-heappoison")]
pub(crate) const VALIDATE_INTERVAL: u64 = 8;

/// B1347: `debug-dealloc-diag` full-free-list validation cadence. Coarser than
/// heappoison's every-8 (no per-block poison memset here, but the walk is still
/// O(free-nodes)), chosen so a fast `debug-boot,debug-dealloc-diag` boot stays
/// in the ~tens-of-seconds range while narrowing corruption-to-detection from
/// "millions of ops (until zram stumbles)" to "≤32 deallocs of the stale write".
#[cfg(feature = "debug-dealloc-diag")]
pub(crate) const DIAG_VALIDATE_INTERVAL: u64 = 32;

/// B1347: depth of the recent-kalloc-op ring dumped on a tight-mode detection
/// (`recent.rs`).
#[cfg(feature = "debug-dealloc-diag")]
pub(crate) const RECENT_N: usize = 48;

/// Smallest freed block a hardware write-watchpoint is armed on
/// (`debug-hw-watchpoint`). A live first pass watching EVERY freed block was
/// pure noise (337 distinct call sites in one ~35s boot, all resolving to
/// kalloc's own add_free_region/memcpy legitimately reusing the address moments
/// later — kalloc serves every kernel allocation, so small/hot sizes recycle
/// within microseconds). Blocks at/above this size sit on the free list
/// appreciably longer before legitimate reuse, while still covering the
/// 4128-byte victim an earlier "kalloc invalid free ptr=... size=4128" sample
/// named directly.
#[cfg(feature = "debug-hw-watchpoint")]
pub(crate) const WATCHPOINT_MIN_SIZE: usize = 512;
