#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
//! Electric-fence UAF-writer localizer (C213, debug-efence).
//!
//! The ~90% boot heap corruptor is a use-after-free: a stale pointer writes a
//! freed static-heap block's object header (offset 0/8). Audit + software
//! validators name only the *detector* (the later kalloc op that walks the
//! free list), never the *writer*. Only a hardware fault-on-write on the freed
//! block names the writer's RIP.
//!
//! This routes every small allocation (`size <= OBJ_MAX`) to its OWN 4 KiB
//! page in a dedicated kernel-VA arena. On free the page flips **read-only**;
//! a stale write to it takes a kernel `#PF` whose `rip` = the writer and `cr2`
//! = the fenced VA (in this arena's distinctive `0xffff_fc00_…` window) — the
//! existing fault oops prints exactly that. Freed pages stay RO in a FIFO;
//! only under arena pressure is the OLDEST recycled (RW again), so the most
//! recent ~`EFENCE_PAGES` frees — which is where a UAF write lands — stay
//! protected.
//!
//! Frames are pre-mapped RW at `init` so the alloc/free hot path takes no
//! nested tracked lock (see `sync::Efence` rank note). Debug-only; `init` is a
//! no-op unless `debug-efence` is on.
extern crate alloc;

#[cfg(feature = "debug-efence")]
mod arena;

/// Reserve the arena and install the kalloc routing hooks. No-op unless
/// `debug-efence`. Must run after PMM+MMU are up and BEFORE the first user
/// address space is forked (so the arena's kernel-half PT entries are in the
/// master every later AS copies) and before the allocation-heavy boot so early
/// small objects get fenced. # C: O(EFENCE_PAGES) one-time.
pub fn init() {
    #[cfg(feature = "debug-efence")]
    arena::init();
}
