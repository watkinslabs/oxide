//! zram compressed-RAM block device.
#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

// Module manifest:
// - control: zram-control device lifecycle.
// - state: per-device configuration, slots, and statistics.
// - io: block-device read/write/discard implementation.
// - writeback: backing-disk page transitions and extent ownership.
// - zsmalloc: Linux-shaped stable-handle compressed-object allocator.
// - state/tracking: canonical per-slot state snapshots for the optional
//   CONFIG_ZRAM_MEMORY_TRACKING-equivalent debugfs ABI.
// - tests: hosted driver contract tests.

mod control;
mod deflate;
mod io;
mod lz4;
mod lzo;
mod state;
mod writeback;
mod zsmalloc;
#[cfg(test)]
mod tests;

pub use control::{by_index, by_name, indices, hot_add, hot_remove, init, init_with_num_devices, reclaim_pages, reclaimable_pages, DEFAULT_DEVICE_INDEX, DEFAULT_DEVICE_NAME, DEFAULT_NUM_DEVICES, ZRAM_BLOCK_DRIVER};
pub use state::{Zram, ZramStats, ZRAM_BLOCK_SIZE, ZRAM_COMP_ALGORITHM, ZRAM_RECOMP_ALGORITHM, ZRAM_DEBUG_STAT_VERSION, ZRAM_WRITEBACK_ACCOUNTING_BYTES, ZRAM_WRITEBACK_BATCH_SIZE_DEFAULT};
#[cfg(feature = "memory-tracking")]
pub use state::ZramBlockState;
pub use zsmalloc::{install_page_provider, page_provider_ready, PageProvider};
