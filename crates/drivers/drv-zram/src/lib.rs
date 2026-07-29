//! zram compressed-RAM block device.
#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
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
mod eight42;
mod io;
mod lz4;
mod lz4hc;
mod lzo;
mod lzorle;
mod state;
mod writeback;
mod zstd;
mod zsmalloc;
#[cfg(test)]
mod tests;

pub use control::{by_index, by_name, indices, hot_add, hot_remove, init, init_with_num_devices, reclaim_pages, reclaimable_pages, DEFAULT_DEVICE_INDEX, DEFAULT_DEVICE_NAME, DEFAULT_NUM_DEVICES, ZRAM_BLOCK_DRIVER};
pub use state::{Zram, ZramStats, ZRAM_BLOCK_SIZE, ZRAM_COMP_ALGORITHM, ZRAM_DEBUG_STAT_VERSION, ZRAM_WRITEBACK_ACCOUNTING_BYTES, ZRAM_WRITEBACK_BATCH_SIZE_DEFAULT};
#[cfg(feature = "memory-tracking")]
pub use state::ZramBlockState;
pub use zsmalloc::{install_page_provider, page_provider_ready, PageProvider};
