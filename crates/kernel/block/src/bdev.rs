// Block-device page cache — the address space a raw `/dev/<disk>` open reads
// and writes through (Linux `bdev->bd_mapping`, the inode of the block special
// file on the internal blockdev filesystem).
//
// Module manifest:
//   `mapping.rs`    — `BdevMapping`: resident pages + the dirty tag set, and
//                     the byte-granular cached `read_at`/`write_at`.
//   `writeback.rs`  — the two-pass writeback surface: `fdatawrite` (submit),
//                     `fdatawait_keep_errors` (wait), `write_and_wait`
//                     (`fsync`), plus range invalidation.
//   `coherence.rs`  — `CoherentDev`: the decorator that keeps a filesystem's
//                     own device I/O and this cache from disagreeing, and the
//                     pure request-range → page-index arithmetic.
//   `sync.rs`       — `sync_bdevs(wait)`, the device half of `sync(2)`.
//
// Why it exists: without it, a write to a block-device fd went straight to the
// driver and `sync(2)`'s device pass had nothing to submit, so its submit half
// was structurally empty and its wait half degenerated into a per-disk barrier.

mod coherence;
mod mapping;
mod sync;
mod writeback;
#[cfg(test)]
mod tests;

pub use coherence::{page_span, CoherentDev};
pub use mapping::BdevMapping;
pub use sync::sync_bdevs;
