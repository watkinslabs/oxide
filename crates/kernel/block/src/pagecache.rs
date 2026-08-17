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
//   `frames.rs`    — handing a cached page to a user page table: the address it
//                    already has, and the conversion that gives it one.
//   `query.rs`     — asking a mapping what it holds without changing it, and
//                    the best-effort eviction that is a hint, not a truncate.
//   `daemon.rs`    — `kflushd`, per target.
//   `store.rs`     — a cached page's storage: a heap buffer until something
//                    asks to MAP the page, the machine frame it was moved into
//                    from then on, and the installed frame provider that
//                    conversion goes through.
//
// Backing-store dispatch: a `PageCache` used over a raw device installs a
// device writeback target itself; a filesystem that maps `(InodeId, file_off)`
// onto its own physical blocks installs its own via `set_writeback`. The cache
// never learns an FS layout.
//
// Two reconciliations with the `17§4.1` struct, both deliberate and both
// visible in `page.rs`:
//   - `pfn: Pfn` is a `PageBuf`: a heap buffer while nothing maps the page, and
//     the machine frame the bytes were MOVED into once something does. The
//     conversion is one-way and in place, so a page never holds two copies of
//     itself. It exists because a user page table can point at a frame and
//     cannot point at a heap buffer: without it a shared writable `mmap` of a
//     file cached here falls back to a private copy-on-write page, and an
//     `msync` of that page reports success having persisted nothing. It is on
//     demand rather than always because the frame-lifetime contract — a
//     refcount per mapper, a mapcount the eviction guard reads, a buddy round
//     trip on free — is worth paying per mapped page and not per cached page.
//   - `inode: Weak<dyn Inode>` is an opaque `InodeId`. The back-reference
//     exists for reclaim, which needs to reach a page's mapping from a list
//     entry; that entry holds `Weak<Mapping>` directly, so the page carries
//     the identity and the list carries the reference.

mod cache;
mod daemon;
mod frames;
mod global;
mod mapping;
mod page;
mod query;
mod radix;
mod store;
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
pub use store::{frames_available, install_frame_provider, FrameProvider, PageBuf};
pub use writeback::{flush_pass, reclaimable_pages, shrink, DevWriteback, Sink};
