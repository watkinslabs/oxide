use alloc::string::String;
use alloc::sync::Arc;

use crate::inode::InodeRef;

use super::Dentry;

/// `d_hash`: hash the name portion (parent salt is folded in by the VFS).
pub type DHashFn = fn(name: &str) -> u32;
/// `d_compare`: true iff `name` matches the cached dentry `cand`.
pub type DCompareFn = fn(name: &str, cand: &Dentry) -> bool;
/// `d_revalidate`: false means the cached dentry is stale.
pub type DRevalidateFn = fn(d: &Arc<Dentry>, reval: bool) -> bool;
/// `d_weak_revalidate`: final-component weak revalidation from `complete_walk`.
pub type DWeakRevalidateFn = fn(d: &Arc<Dentry>, reval: bool) -> bool;
/// `d_delete`: true means final `dput` frees instead of LRU-caching.
pub type DDeleteFn = fn(d: &Dentry) -> bool;
/// `d_release`: dentry is being freed.
pub type DReleaseFn = fn(d: &Dentry);
/// `d_iput`: inode is being disassociated from this dentry.
pub type DIputFn = fn(d: &Dentry, inode: InodeRef);
/// `d_dname`: render a pseudo dentry's complete display path.
pub type DDnameFn = fn(d: &Dentry) -> String;
/// `d_init`: allocation-time per-dentry initializer.
pub type DInitFn = fn(d: &Dentry);
/// `d_prune`: dentry is about to be pruned/killed from cache.
pub type DPruneFn = fn(d: &Dentry);

/// Linux `dentry_operations`. All hooks are `'static` fn pointers, not `dyn`.
pub struct DentryOps {
    pub d_hash:       Option<DHashFn>,
    pub d_compare:    Option<DCompareFn>,
    pub d_revalidate: Option<DRevalidateFn>,
    pub d_weak_revalidate: Option<DWeakRevalidateFn>,
    pub d_delete:     Option<DDeleteFn>,
    pub d_release:    Option<DReleaseFn>,
    pub d_iput:       Option<DIputFn>,
    pub d_dname:      Option<DDnameFn>,
    pub d_init:       Option<DInitFn>,
    pub d_prune:      Option<DPruneFn>,
}

impl DentryOps {
    /// All-default ops vector. # C: O(1)
    pub const fn empty() -> Self {
        DentryOps { d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None }
    }
}
