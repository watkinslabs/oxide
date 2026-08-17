// Page cache per `17§4`.
//
// Module manifest:
//   `radix.rs`     — the page-index radix tree a mapping is indexed by (`17§4.1`).
//   `page.rs`      — `CachedPage`, its `PG_*` flag word, and the `PG_LOCKED`
//                    bit with its hashed waiter table (`17§4.2` step 5).
//   `mapping.rs`   — one inode's pages: the tree, its dirty list, and the
//                    `Writeback` target those dirty pages go to (`17§4.3`).
//   `global.rs`    — machine-wide state: the two-list LRU (`17§4.4`), the
//                    dirty-inode list, the dirty count and its thresholds.
//   `writeback.rs` — the passes: `fsync`/flusher writeback, and reclaim.
//   `cache.rs`     — `PageCache`, the public surface.
//   `query.rs`     — asking a mapping what it holds without changing it, and
//                    the best-effort eviction that is a hint, not a truncate.
//   `daemon.rs`    — `kflushd`, per target.
//
// Backing-store dispatch: a `PageCache` used over a raw device installs a
// device writeback target itself; a filesystem that maps `(InodeId, file_off)`
// onto its own physical blocks installs its own via `set_writeback`. The cache
// never learns an FS layout.
//
// Two reconciliations with the `17§4.1` struct, both deliberate and both
// visible in `page.rs`:
//   - `pfn: Pfn` is a heap page buffer. A cached page here is never handed to
//     a user PTE — the mmap fault path copies out of it — so a PMM frame would
//     buy nothing and cost the frame-lifetime rules a mapped frame carries.
//   - `inode: Weak<dyn Inode>` is an opaque `InodeId`. The back-reference
//     exists for reclaim, which needs to reach a page's mapping from a list
//     entry; that entry holds `Weak<Mapping>` directly, so the page carries
//     the identity and the list carries the reference.

mod cache;
mod daemon;
mod global;
mod mapping;
mod page;
mod query;
mod radix;
mod writeback;
#[cfg(test)]
pub(crate) mod tests;

pub use cache::PageCache;
pub use daemon::{spawn_daemons, wake_flusher};
pub use global::{
    background_threshold, dirty_action, dirty_expired, dirty_limit, install_clock,
    install_totalram_pages, nr_cached, nr_dirty, nr_writeback, totalram_pages, DirtyAction,
    DIRTY_BACKGROUND_RATIO, DIRTY_EXPIRE_NS, DIRTY_RATIO, WRITEBACK_INTERVAL_NS,
};
pub use mapping::{Mapping, PageOut, Writeback};
pub use page::CachedPage;
pub use query::PageState;
pub use radix::RadixTree;
pub use writeback::{flush_pass, reclaimable_pages, shrink, DevWriteback, Sink};
