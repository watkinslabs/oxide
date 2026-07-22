//! dcache primitives per Linux `fs/dcache.c`.
//!
//! Module manifest:
//! - `hash`: global `(parent,name)` dentry hash table and seqcount probes.
//! - `alloc`: root/child/pseudo allocation, lookup, revalidation, instantiate, add.
//! - `parallel`: in-flight parallel lookup placeholders.
//! - `reclaim`: dcache LRU, shrinkers, subtree/sb/umount prune, alias prune.
//! - `lifecycle`: dget/dput, kill, drop, delete, unlink.
//! - `rename`: global rename seqcount and d_move.
//! - `alias`: disconnected aliases and d_splice_alias.
//! - `invalidate`: subtree invalidation and mount detach.
//! - `tests`: dcache module tests.

mod alias;
mod alloc;
mod hash;
mod invalidate;
mod lifecycle;
mod parallel;
mod reclaim;
mod rename;

pub use alias::{d_obtain_alias, d_splice_alias};
pub use alloc::{d_add, d_add_negative, d_alloc, d_alloc_pseudo, d_drop_child, d_instantiate, d_lookup, d_lookup_reval, d_make_root, d_weak_revalidate};
pub use invalidate::d_invalidate;
pub use lifecycle::{d_delete, d_drop, d_unlink, dget, dput};
pub use parallel::{d_alloc_parallel, d_lookup_done, DParLookup};
pub use reclaim::{dcache_lru_count, d_prune_aliases, shrink_dcache, shrink_dcache_for_umount, shrink_dcache_memory, shrink_dcache_parent, shrink_dcache_sb};
pub use rename::{d_move, rename_lock_read_begin, rename_lock_retry};
#[cfg(feature = "debug-heappoison")]
pub use hash::debug_scan_d_op_sanity;

#[cfg(test)]
mod tests;
