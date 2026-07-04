// Dentry per `16§2`. Holds parent / name / cached inode pointer.
// Negative dentries (`inode == None`) cache "name not found" results
// per `16§4` so repeated path lookups don't re-walk the FS.
//
// B3 adds the Linux scalability/ops layers on top of the WP1 primitives:
//   - `QStr`: precomputed `full_name_hash` (Linux `struct qstr`), salted by
//     the parent pointer so the global `dentry_hashtable` (in `dcache.rs`)
//     can key on `(d_parent, d_name.hash)` for O(1) lookup.
//   - `Lockref`: the VFS-visible `d_count` pin (Linux `lockref`). Distinct
//     from the `Arc` strong count — see the divergence note on `Lockref`.
//   - `DentryOps`: `d_op` function-vector (no `dyn`, all `'static` fn ptrs)
//     invoked at the lookup / dput / free lifecycle points.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use sync::{Dentry as DentryClass, Inode as InodeClass, RwLock};

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;
use crate::types::FileType;

pub mod flags;
mod constructors;
mod lifecycle;
mod lockref;
mod ops;
mod paths;
mod qstr;
pub use flags::*;
pub use lockref::{Lockref, LOCKREF_DEAD};
pub use ops::*;
pub use qstr::{QStr, DNAME_INLINE_LEN};

use lifecycle::dentry_iput;

/// Presence-bit set for `d_op` (Linux `d_set_d_op`): a `D_OP_*` bit per
/// non-NULL hook, so the hot path branches on `d_flags` not a pointer deref.
/// `None` ⇒ no bits (all-default ops). # C: O(1)
fn op_flags_for(d_op: Option<&'static DentryOps>) -> u32 {
    let o = match d_op { Some(o) => o, None => return 0 };
    let mut f = 0;
    if o.d_hash.is_some()       { f |= D_OP_HASH; }
    if o.d_compare.is_some()    { f |= D_OP_COMPARE; }
    if o.d_revalidate.is_some() { f |= D_OP_REVALIDATE; }
    if o.d_weak_revalidate.is_some() { f |= D_OP_WEAK_REVALIDATE; }
    if o.d_delete.is_some()     { f |= D_OP_DELETE; }
    if o.d_dname.is_some()      { f |= D_OP_DNAME; }
    if o.d_prune.is_some()      { f |= D_OP_PRUNE; }
    f
}

/// Cached-type bits for an optional inode (Linux `__d_entry_type`): the
/// `S_IFMT` class folded to a `D_*_TYPE`, or `D_MISS_TYPE` when negative.
/// # C: O(1)
fn type_bits_for(inode: &Option<InodeRef>) -> u32 {
    match inode {
        None => D_MISS_TYPE,
        Some(i) => match i.file_type() {
            FileType::Directory => D_DIRECTORY_TYPE,
            FileType::Regular   => D_REGULAR_TYPE,
            FileType::Symlink   => D_SYMLINK_TYPE,
            FileType::CharDev | FileType::BlockDev | FileType::Fifo | FileType::Socket => D_SPECIAL_TYPE,
        },
    }
}

/// Single path-component cache node — Linux `struct dentry`. Keyed by
/// `(d_parent, d_name.hash)` in the global `dentry_hashtable` (`dcache.rs`);
/// NEVER by an absolute path string.
pub struct Dentry {
    /// `d_parent`. None = root / floating.
    parent: Option<Arc<Dentry>>,
    /// `d_name` — Linux `qstr` (name + precomputed `full_name_hash`).
    name:   QStr,
    /// `d_inode`. None = NEGATIVE dentry (`16§4`).
    inode:  RwLock<Option<InodeRef>, InodeClass>,
    /// `d_sb` — owning superblock backref. NON-owning `Weak`: the SB owns
    /// `s_root` (strong) and outlives every dentry; making this strong
    /// would form an Arc cycle that leaks the tree at umount. Default
    /// `Weak::new()` for dentries built before their fs owns a SuperBlock
    /// (WP6-pending backends, anon-fd factories).
    sb: Weak<SuperBlock>,
    /// `d_op` — per-dentry operation vector, inherited from the parent at
    /// `new_child` (Linux `s_d_op` propagated at `d_alloc`). `None` = default.
    d_op: Option<&'static DentryOps>,
    /// `d_count` — VFS-visible pin count (Linux `lockref`). 0 = unused,
    /// eligible for the LRU/shrinker. See `Lockref` divergence note.
    d_count: Lockref,
    /// `d_flags`.
    d_flags: AtomicU32,
    /// `d_subdirs`: resolved children by component name (`16§4`). Retained as
    /// the subtree-teardown / `d_invalidate` index + cheap readdir; the
    /// authoritative O(1) lookup is the global `dentry_hashtable`. Per-(parent,
    /// name) — there is no global path→dentry map. Lock class `Dentry`.
    children: RwLock<BTreeMap<String, Arc<Dentry>>, DentryClass>,
    /// `d_time` — fs-private revalidation stamp (Linux `d_time`). The owning fs
    /// sets it in lookup/`d_revalidate` (a version/generation); the VFS only
    /// stores it. Atomic — a dentry is shared via `Arc`. # consumers: d_revalidate.
    d_time: AtomicU64,
    /// `d_fsdata` — fs-private per-dentry token (Linux `d_fsdata` void*). A
    /// pointer-sized opaque value the owning fs interprets (`0` = unset).
    d_fsdata: AtomicU64,
    /// `d_seq` — per-dentry seqcount (Linux `dentry->d_seq`) guarding the
    /// `d_parent`/`d_name` binding against a concurrent `d_move` (rename) during
    /// a lock-free walk. EVEN = stable, ODD = a `d_move` is rehoming this name.
    /// A lockless reader snapshots it (`read_seqbegin`), reads parent/name, then
    /// `read_seqretry`s; an odd value or a changed generation means "renamed
    /// under me — retry the walk". The bucket seqcount (`dcache.rs`) protects the
    /// hash chain; THIS protects an individual dentry's identity across a move.
    d_seq: AtomicU32,
    /// D3/D37: `true` when this dentry holds ONE counted `i_count` reference on
    /// its inode (Linux: a positive dentry pins its inode via the `iget` ref
    /// `__d_instantiate` consumed). Taken by [`Dentry::grab_inode_hold`] from the
    /// dcache binding primitives (`d_add`/`d_instantiate`/`d_make_root`/
    /// `d_alloc_pseudo`/`d_obtain_alias`); released — exactly once — by
    /// [`Dentry::set_inode`]`(None)` or `Dentry::drop` via [`dentry_iput`].
    /// A dentry built through the RAW constructors ([`Dentry::new`] etc.) without
    /// a dcache primitive stays UNcounted (`false`), so it neither bumps nor
    /// releases `i_count` — the open-`File` igrab/iput path is then the only
    /// counted hold (keeps `file_iput_igrab` balanced). `igrab`/`iput` touch the
    /// SB icache (rank 60 > Dentry 50 > Inode 40), always taken with no lower
    /// lock held, so the ordering is ascending.
    counted: AtomicBool,
}

impl Dentry {
    /// `d_time` — fs-private revalidation stamp (Linux `d_time`). # C: O(1)
    pub fn d_time(&self) -> u64 { self.d_time.load(Ordering::Acquire) }
    /// Set `d_time` (owning fs, in lookup/`d_revalidate`). # C: O(1)
    pub fn set_d_time(&self, v: u64) { self.d_time.store(v, Ordering::Release); }
    /// `d_fsdata` — fs-private per-dentry token (`0` = unset). # C: O(1)
    pub fn d_fsdata(&self) -> u64 { self.d_fsdata.load(Ordering::Acquire) }
    /// Set `d_fsdata` (owning fs). # C: O(1)
    pub fn set_d_fsdata(&self, v: u64) { self.d_fsdata.store(v, Ordering::Release); }

    /// `d_seq` raw snapshot — the per-dentry rename seqcount. # C: O(1)
    pub fn d_seq(&self) -> u32 { self.d_seq.load(Ordering::Acquire) }

    /// Begin a lock-free read of `d_parent`/`d_name` (Linux
    /// `read_seqcount_begin`): spin until the seqcount is EVEN (no `d_move` in
    /// flight) and return that even snapshot. Pair with `read_seqretry` after
    /// reading the name/parent. # C: O(1) amortized
    pub fn read_seqbegin(&self) -> u32 {
        loop {
            let s = self.d_seq.load(Ordering::Acquire);
            if s & 1 == 0 { return s; }
            core::hint::spin_loop();
        }
    }

    /// Validate a lock-free read (Linux `read_seqcount_retry`): `true` ⇒ a
    /// `d_move` raced the read (seqcount advanced or is mid-write), so the caller
    /// must retry the walk. # C: O(1)
    pub fn read_seqretry(&self, start: u32) -> bool {
        core::sync::atomic::fence(Ordering::Acquire);
        self.d_seq.load(Ordering::Acquire) != start
    }

    /// Open the rename write window on this dentry's name binding (Linux
    /// `write_seqcount_begin` at the top of `__d_move`): advance `d_seq` to ODD
    /// so a concurrent lock-free reader sees the in-flight rename and retries.
    /// MUST be paired with `seq_write_end`. # C: O(1)
    pub fn seq_write_begin(&self) { self.d_seq.fetch_add(1, Ordering::Release); }

    /// Close the rename write window (Linux `write_seqcount_end`): advance
    /// `d_seq` back to EVEN — a new generation, so any reader that snapshotted
    /// the pre-move value fails `read_seqretry`. # C: O(1)
    pub fn seq_write_end(&self) { self.d_seq.fetch_add(1, Ordering::Release); }

    /// `d_sb` — owning superblock, if any. # C: O(1)
    pub fn d_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }

    /// `d_op` — per-dentry operation vector, if any. # C: O(1)
    pub fn d_op(&self) -> Option<&'static DentryOps> { self.d_op }

    /// `d_op->d_hash` present, from the `D_OP_HASH` presence bit — no `d_op`
    /// deref (Linux `d_flags & DCACHE_OP_HASH`). # C: O(1)
    pub fn d_has_op_hash(&self) -> bool { self.flags() & D_OP_HASH != 0 }
    /// `d_op->d_compare` present (Linux `DCACHE_OP_COMPARE`). The `__d_lookup`
    /// hot path tests this before calling `d_compare`. # C: O(1)
    pub fn d_has_op_compare(&self) -> bool { self.flags() & D_OP_COMPARE != 0 }
    /// `d_op->d_revalidate` present (Linux `DCACHE_OP_REVALIDATE`). # C: O(1)
    pub fn d_has_op_revalidate(&self) -> bool { self.flags() & D_OP_REVALIDATE != 0 }
    /// `d_op->d_weak_revalidate` present (Linux `DCACHE_OP_WEAK_REVALIDATE`).
    /// `complete_walk` tests this on the final dentry before the one-shot weak
    /// revalidation. # C: O(1)
    pub fn d_has_op_weak_revalidate(&self) -> bool { self.flags() & D_OP_WEAK_REVALIDATE != 0 }
    /// `d_op->d_delete` present (Linux `DCACHE_OP_DELETE`). `dput` tests this
    /// before consulting `d_delete` on the final put. # C: O(1)
    pub fn d_has_op_delete(&self) -> bool { self.flags() & D_OP_DELETE != 0 }
    /// `d_op->d_dname` present (Linux `DCACHE_OP_DNAME`). `d_path`/`dentry_path`
    /// test this to render the name dynamically instead of parent-walking — set
    /// only on `d_alloc_pseudo` dentries (pipe/socket/anon-inode). # C: O(1)
    pub fn d_has_op_dname(&self) -> bool { self.flags() & D_OP_DNAME != 0 }
    /// `d_op->d_prune` present (Linux `DCACHE_OP_PRUNE`). `dentry_kill` tests
    /// this before firing `d_prune` on a dentry about to leave the cache.
    /// # C: O(1)
    pub fn d_has_op_prune(&self) -> bool { self.flags() & D_OP_PRUNE != 0 }

    /// Dynamic path string from `d_op->d_dname`, if this is a pseudo dentry that
    /// renders its own name (Linux `dentry->d_op->d_dname`). `None` ⇒ ordinary
    /// dentry, reconstruct by the parent walk. # C: O(d_dname)
    pub fn d_dname(&self) -> Option<String> {
        if self.flags() & D_OP_DNAME == 0 { return None; }
        self.d_op.and_then(|o| o.d_dname).map(|f| f(self))
    }

    /// Install `d_op` on a freshly built dentry (Linux `d_set_d_op`). Used to
    /// give a subtree root case-insensitive ops before children are spliced.
    /// # C: O(1)
    pub fn set_d_op(self: &Arc<Self>, ops: &'static DentryOps) -> Arc<Self> {
        // Rebuild is unnecessary: d_op is set at construction in real use; this
        // helper rebuilds a root-like dentry with ops for tests/fs setup.
        Self::build(self.parent.clone(), self.name.name(), self.inode.read().clone(), self.sb.clone(), Some(ops), self.flags() & (D_ROOT | D_NEGATIVE))
    }

    /// `d_name.hash` — precomputed `full_name_hash`. # C: O(1)
    pub fn d_hash(&self) -> u32 { self.name.hash }

    /// `d_flags` snapshot. # C: O(1)
    pub fn flags(&self) -> u32 { self.d_flags.load(Ordering::Relaxed) }

    fn set_flag(&self, bit: u32, on: bool) {
        let mut f = self.d_flags.load(Ordering::Relaxed);
        if on { f |= bit; } else { f &= !bit; }
        self.d_flags.store(f, Ordering::Relaxed);
    }

    /// Mark/clear presence in the global `dentry_hashtable` (`D_HASHED`).
    /// # C: O(1)
    pub fn set_hashed(&self, on: bool) { self.set_flag(D_HASHED, on); }
    /// # C: O(1)
    pub fn is_hashed(&self) -> bool { self.flags() & D_HASHED != 0 }
    /// True iff this dentry is absent from the global hashtable (Linux
    /// `d_unhashed` — `!(d_flags & DCACHE_HASHED)`). # C: O(1)
    pub fn is_unhashed(&self) -> bool { self.flags() & D_HASHED == 0 }
    /// True iff this dentry was unlinked while still pinned open (Linux
    /// `d_unlinked`: `d_unhashed(d) && !IS_ROOT(d)`). A removed-but-open file
    /// keeps its parent link but drops out of the hash; `dentry_path` suffixes
    /// its reconstructed name with " (deleted)". A superblock root is never
    /// "unlinked" even while unhashed. # C: O(1)
    pub fn is_unlinked(&self) -> bool { self.is_unhashed() && !self.is_root() }

    /// LRU bookkeeping bits (`16§98`). # C: O(1)
    pub fn set_on_lru(&self, on: bool) { self.set_flag(D_LRU, on); }
    /// # C: O(1)
    pub fn is_on_lru(&self) -> bool { self.flags() & D_LRU != 0 }
    /// # C: O(1)
    pub fn set_referenced(&self, on: bool) { self.set_flag(D_REFERENCED, on); }
    /// # C: O(1)
    pub fn is_referenced(&self) -> bool { self.flags() & D_REFERENCED != 0 }

    /// `d_count` (lockref) snapshot. # C: O(1)
    pub fn d_count(&self) -> i64 { self.d_count.read() }
    /// `dget` accounting — bump `d_count`, mark referenced (two-hand clock).
    /// # C: O(1)
    pub fn inc_count(&self) -> i64 { self.set_referenced(true); self.d_count.get() }
    /// `dput` accounting — drop `d_count`, returning the new value.
    /// # C: O(1)
    pub fn dec_count(&self) -> i64 { self.d_count.put() }

    /// `dget` variant that refuses a dentry mid-kill (Linux `lockref_get_not_dead`,
    /// the `__d_lookup_rcu` pin): returns true when the reference was taken,
    /// false when the dentry is dead (`__dentry_kill` ran `mark_dead`) and the
    /// caller must fall back to the slow `i_op->lookup`. On success marks
    /// referenced (two-hand clock), like `inc_count`. # C: O(1)
    pub fn inc_count_not_dead(&self) -> bool {
        let ok = self.d_count.get_not_dead();
        if ok { self.set_referenced(true); }
        ok
    }

    /// `dget` variant that pins only an already-in-use dentry (Linux
    /// `lockref_get_not_zero`): false when `d_count == 0` (unused, reclaimable)
    /// or dead. # C: O(1)
    pub fn inc_count_not_zero(&self) -> bool {
        let ok = self.d_count.get_not_zero();
        if ok { self.set_referenced(true); }
        ok
    }

    /// Stamp the kill sentinel on `d_count` (Linux `lockref_mark_dead`, at the
    /// top of `__dentry_kill`): after this no `inc_count_not_dead` /
    /// `inc_count_not_zero` can resurrect the dentry. # C: O(1)
    pub fn mark_dead(&self) { self.d_count.mark_dead(); }

    /// True iff this dentry's lockref is dead — a kill is in progress. # C: O(1)
    pub fn is_dead(&self) -> bool { self.d_count.is_dead() }

    /// True iff this dentry is a superblock root (`D_ROOT`). # C: O(1)
    pub fn is_root(&self) -> bool { self.flags() & D_ROOT != 0 }

    /// True iff this is an anonymous disconnected dentry (`D_DISCONNECTED`):
    /// parentless, no path, on the SB's `s_anon` list (Linux `d_obtain_alias`).
    /// # C: O(1)
    pub fn is_disconnected(&self) -> bool { self.flags() & D_DISCONNECTED != 0 }

    /// Mark/clear "drop when unused" (Linux `d_mark_dontcache` sets the bit on
    /// every alias of an `I_DONTCACHE` inode). # C: O(1)
    pub fn set_dontcache(&self, on: bool) { self.set_flag(D_DONTCACHE, on); }
    /// True iff `D_DONTCACHE` — the final `dput` must kill, not LRU-cache, this
    /// dentry (Linux `retain_dentry` returns false). # C: O(1)
    pub fn is_dontcache(&self) -> bool { self.flags() & D_DONTCACHE != 0 }

    /// Mark/clear `D_PAR_LOOKUP` — an in-flight parallel lookup placeholder
    /// (Linux `DCACHE_PAR_LOOKUP`, set in `d_alloc_parallel`, cleared in
    /// `__d_lookup_done`). # C: O(1)
    pub fn set_par_lookup(&self, on: bool) { self.set_flag(D_PAR_LOOKUP, on); }
    /// True iff a parallel lookup is still resolving this dentry — the
    /// `DParLookup::Waiter` wake gate (Linux `d_in_lookup`). # C: O(1)
    pub fn is_in_lookup(&self) -> bool { self.flags() & D_PAR_LOOKUP != 0 }

    /// Replace the `DCACHE_ENTRY_TYPE` field with `bits` (one of `D_*_TYPE`),
    /// preserving every other `d_flags` bit. Linux `__d_set_inode_and_type`.
    /// # C: O(1)
    fn set_type(&self, bits: u32) {
        let mut f = self.d_flags.load(Ordering::Relaxed);
        f = (f & !D_TYPE_MASK) | (bits & D_TYPE_MASK);
        self.d_flags.store(f, Ordering::Relaxed);
    }

    /// Cached `DCACHE_ENTRY_TYPE` field — a `D_*_TYPE` value. # C: O(1)
    pub fn d_type(&self) -> u32 { self.flags() & D_TYPE_MASK }

    /// Cached "this dentry has no inode" (Linux `d_is_negative`). Reads the
    /// stamped type bits — no `d_inode` deref, unlike `is_negative`. # C: O(1)
    pub fn d_is_miss(&self) -> bool { self.d_type() == D_MISS_TYPE }
    /// Cached "this dentry has an inode" (Linux `d_is_positive`). # C: O(1)
    pub fn d_is_positive(&self) -> bool { !self.d_is_miss() }
    /// Cached "directory" (Linux `d_is_dir`). The walker branches on this
    /// without locking + dereferencing `d_inode`. # C: O(1)
    pub fn d_is_dir(&self) -> bool { self.d_type() == D_DIRECTORY_TYPE }
    /// Cached "a lookup may descend here" (Linux `d_can_lookup`) — directory.
    /// # C: O(1)
    pub fn d_can_lookup(&self) -> bool { self.d_is_dir() }
    /// Cached "regular file" (Linux `d_is_reg`). # C: O(1)
    pub fn d_is_reg(&self) -> bool { self.d_type() == D_REGULAR_TYPE }
    /// Cached "symlink" (Linux `d_is_symlink`) — gate before a symlink follow.
    /// # C: O(1)
    pub fn d_is_symlink(&self) -> bool { self.d_type() == D_SYMLINK_TYPE }
    /// Cached "char/block/fifo/socket" (Linux `d_is_special`). # C: O(1)
    pub fn d_is_special(&self) -> bool { self.d_type() == D_SPECIAL_TYPE }

    /// # C: O(1)
    pub fn name(&self) -> &str { self.name.name() }

    /// # C: O(1)
    pub fn parent(&self) -> Option<&Arc<Dentry>> { self.parent.as_ref() }

    /// Linux `d_ancestor(p1, p2)` (`fs/dcache.c`): if `self` (`p1`) is a STRICT
    /// ancestor of `descendant` (`p2`) in the same dentry tree, return the
    /// direct child of `self` lying on the path down to `descendant`; else
    /// `None`. Walks `d_parent` from `descendant` up to its tree root, matching
    /// parents by `Arc` pointer identity. `self == descendant` returns `None`
    /// (not a strict ancestor) — mirrors Linux's `!IS_ROOT(p)` loop. # C: O(depth)
    pub fn d_ancestor(self: &Arc<Self>, descendant: &Arc<Self>) -> Option<Arc<Self>> {
        let mut p = descendant.clone();
        while let Some(parent) = p.parent.clone() {
            if Arc::ptr_eq(&parent, self) { return Some(p); }
            p = parent;
        }
        None
    }

    /// Linux `is_subdir(new_dentry, old_dentry)` (`fs/dcache.c`): true iff
    /// `self` (`new`) IS `ancestor` (`old`) or lies inside `ancestor`'s subtree
    /// (`ancestor` is a strict ancestor of `self`). The rename keystone loop
    /// check — `do_rename` rejects moving a directory into its own descendant
    /// with `EINVAL` — plus `is_path_reachable`. # C: O(depth)
    pub fn is_subdir_of(self: &Arc<Self>, ancestor: &Arc<Self>) -> bool {
        Arc::ptr_eq(self, ancestor) || ancestor.d_ancestor(self).is_some()
    }

    /// Identity key match for the global hash table: parent pointer eq +
    /// precomputed hash eq + name compare (`d_op->d_compare` or byte-exact).
    /// `parent` is the raw `*const Dentry` of the query parent.
    /// # C: O(name.len())
    pub fn key_matches(&self, parent: *const Dentry, qhash: u32, name: &str) -> bool {
        if self.name.hash != qhash { return false; }
        match self.parent.as_ref() {
            Some(p) => if Arc::as_ptr(p) != parent { return false; },
            None    => return false, // root/floating dentries aren't parent-keyed
        }
        // Fast path branches on the `D_OP_COMPARE` presence bit (Linux
        // `__d_lookup`: `parent->d_flags & DCACHE_OP_COMPARE`), skipping the
        // `d_op` deref entirely for the all-default common case.
        if self.flags() & D_OP_COMPARE == 0 { return self.name.name() == name; }
        match self.d_op.and_then(|o| o.d_compare) {
            Some(cmp) => cmp(name, self),
            None      => self.name.name() == name,
        }
    }

    /// Cached inode, if positive. Read-locks the slot. # C: O(1)
    pub fn inode(&self) -> Option<InodeRef> { self.inode.read().clone() }

    /// True iff this is a negative dentry (cached "not found"). # C: O(1)
    pub fn is_negative(&self) -> bool { self.inode.read().is_none() }

    /// Replace the cached inode (positive ↔ negative transitions on
    /// `create` / `unlink`). Fires `d_op->d_iput` when a positive inode is
    /// disassociated. # C: O(1)
    pub fn set_inode(&self, inode: Option<InodeRef>) {
        let neg = inode.is_none();
        let type_bits = type_bits_for(&inode);
        let old = { let mut g = self.inode.write(); core::mem::replace(&mut *g, inode) };
        if let Some(ref old_inode) = old {
            if let Some(f) = self.d_op.and_then(|o| o.d_iput) { f(self, old_inode.clone()); }
        }
        self.set_flag(D_NEGATIVE, neg);
        self.set_type(type_bits); // re-stamp DCACHE_ENTRY_TYPE (Linux __d_set_inode_and_type)
        // D3/D37: this dentry stopped referencing `old`. If it held a COUNTED
        // `i_count` reference on it (a dcache primitive called `grab_inode_hold`),
        // release that reference now (Linux `dentry_iput`). The 1→0 drop routes
        // through the owning SB's `iput` (drop_inode/evict_inode lifecycle).
        // Done AFTER the inode write lock is dropped above, and `igrab`/`iput`
        // take no lock below the icache (rank 60) — ascending order, no deadlock.
        if let Some(old_inode) = old {
            if self.counted.swap(false, Ordering::AcqRel) { dentry_iput(old_inode); }
        }
    }

    /// D3/D37: take ONE counted `i_count` reference for this (now positive)
    /// dentry's inode hold (Linux `__d_instantiate` consuming the `iget` ref —
    /// here an explicit `igrab` so the dentry alias is reflected in `i_count`).
    /// Called by the dcache binding primitives right after a dentry becomes
    /// positive. Idempotent (`counted` gate): a dentry holds AT MOST one counted
    /// reference; the matching release is `set_inode(None)` / `Drop` via
    /// [`dentry_iput`]. No-op on a negative dentry. `igrab` is a lone atomic on
    /// `Inode::i_count` (no lock), so this is safe to call under any held
    /// dcache/inode lock. # C: O(1)
    pub fn grab_inode_hold(&self) {
        let inode = match self.inode() { Some(i) => i, None => return };
        if !self.counted.swap(true, Ordering::AcqRel) { inode.igrab(); }
    }

    /// True iff this dentry currently holds a counted `i_count` reference on its
    /// inode (test probe / invariant assertions). # C: O(1)
    #[doc(hidden)]
    pub fn holds_icount(&self) -> bool { self.counted.load(Ordering::Acquire) }

    /// Cached child dentry for `name`, if previously resolved (the
    /// per-parent `d_subdirs` index; the global table is the lookup fast
    /// path). # C: O(log N_children)
    pub fn cached_child(&self, name: &str) -> Option<Arc<Dentry>> {
        self.children.read().get(name).cloned()
    }

    /// Insert (or replace) a resolved child dentry under `name`.
    /// Returns the dentry now in the cache (an existing entry wins a
    /// race, so all walkers share one dentry per (parent,name)).
    /// # C: O(log N_children)
    pub fn cache_child(&self, name: &str, child: Arc<Dentry>) -> Arc<Dentry> {
        let mut g = self.children.write();
        g.entry(String::from(name)).or_insert(child).clone()
    }

    /// Drop a cached child (e.g. on unlink/rename so a stale positive
    /// dentry isn't reused). # C: O(log N_children)
    pub fn forget_child(&self, name: &str) {
        self.children.write().remove(name);
    }

    /// Snapshot of the live children (for `d_invalidate` subtree teardown).
    /// # C: O(N_children)
    pub fn children_snapshot(&self) -> Vec<Arc<Dentry>> {
        self.children.read().values().cloned().collect()
    }

    /// `D_MOUNTED` hint — true iff ≥1 mount (any namespace) is attached on this
    /// dentry (Linux `d_mountpoint`: `d_flags & DCACHE_MOUNTED`). Refcounted via
    /// the `struct mountpoint` `m_count` in [`crate::mntns`]. # C: O(1)
    pub fn is_mounted(&self) -> bool { self.flags() & D_MOUNTED != 0 }

    /// Set `D_MOUNTED` (Linux `d_set_mounted`). Called on the `m_count` 0→1
    /// create path in [`crate::mntns::get_mountpoint`]. # C: O(1)
    pub(crate) fn set_mounted(&self) { self.d_flags.fetch_or(D_MOUNTED, Ordering::Relaxed); }

    /// Clear `D_MOUNTED` (Linux `__put_mountpoint` last drop). Called on the
    /// `m_count` 1→0 drop in [`crate::mntns::put_mountpoint`]. # C: O(1)
    pub(crate) fn clear_mounted(&self) { self.d_flags.fetch_and(!D_MOUNTED, Ordering::Relaxed); }

}
