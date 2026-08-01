// Global frame-refcount INVARIANT harness for fork-COW (`11§7`, `11§8`).
//
// Why this exists: the existing `tests_cow_isolation.rs` checks refcount
// against a *hand-maintained* expectation in a fixed 3-way script. It never
// asserts the TRUE global invariant
//
//     refcount(pa) == (# live user PTEs across ALL address spaces -> pa)
//                     + base_holds(pa)            // inode pin for shmem
//
// after every operation, and never randomizes the op stream. A subtle
// fork-COW refcount UNDER-COUNT (a frame whose refcount drops below its live
// mapping count, then is freed + reused while still mapped -> the live-gnome
// random-process SIGSEGV) is invisible to that script.
//
// This harness drives the REAL production code paths:
//   * `AddressSpace::fork_cow_pages`           (fork / fork-of-child)
//   * `AddressSpace::handle_page_fault_cow_rmap` with the SAME closure
//     wiring the kernel fault dispatcher uses (real inc/dec/refcount/alloc)
//   * `AddressSpace::munmap` + a faithful model of `glue_munmap` /
//     `as_teardown` (unmap-then-dec per present leaf)
// over a multi-AS page-table model (one leaf map per root, switched via
// `MmuOps::activate` like CR3), a real struct-page refcount map, a real
// free-list with the production "never hand out a refcount!=0 frame" guard,
// and asserts the global invariant after EVERY op across 200k randomized ops.
//
// A refcount UNDER-COUNT shows up two ways, both asserted here:
//   (1) a live PTE points at a frame whose refcount is 0 (freed while mapped),
//   (2) refcount(pa) < live-PTE-count(pa) + base.
// An over-count (leak) is asserted too (refcount > count) so the harness is a
// strict equality check, not a one-sided one.

#![cfg(test)]

mod model;
mod driver;
mod cases;
mod rss;

use model::*;
use driver::*;
