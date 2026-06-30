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
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

use sync::{Dentry as DentryClass, Inode as InodeClass, RwLock};

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;
use crate::types::FileType;

/// `d_flags` bits (Linux `include/linux/dcache.h` subset).
pub const D_ROOT:       u32 = 0x0001; // this dentry is a superblock root
pub const D_NEGATIVE:   u32 = 0x0002; // d_inode == None
pub const D_HASHED:     u32 = 0x0004; // present in the global dentry_hashtable
pub const D_REFERENCED: u32 = 0x0008; // recently used — LRU two-hand-clock bit
pub const D_LRU:        u32 = 0x0010; // currently linked on the dcache LRU
pub const D_DISCONNECTED: u32 = 0x0020; // anonymous (parentless) alias, on s_anon
/// Drop this dentry the instant it goes unused — Linux `DCACHE_DONTCACHE`
/// (`d_mark_dontcache`, propagated from `I_DONTCACHE`). `retain_dentry` returns
/// false for it, so the final `dput` `dentry_kill`s instead of LRU-caching;
/// repeated lookups of a `DONTCACHE` name therefore never accumulate idle
/// dentries (DAX / on-demand fs that want their inodes evicted promptly).
pub const D_DONTCACHE:  u32 = 0x1000;
/// An in-flight PARALLEL lookup is resolving this (parent,name) — Linux
/// `DCACHE_PAR_LOOKUP` (`d_alloc_parallel`). Set on the placeholder dentry the
/// LEADER walker installs in the in-lookup table before it runs the slow
/// `i_op->lookup`; concurrent walkers for the SAME key find the placeholder and
/// wait on this bit instead of each constructing + racing their own. Cleared by
/// `d_lookup_done` (Linux `__d_lookup_done`) once the leader publishes the
/// resolved (positive or cached-negative) dentry, after which the bit-clear is
/// the waiters' wake condition. Bit position is this file's own layout.
pub const D_PAR_LOOKUP:  u32 = 0x4000;
/// A filesystem is mounted on this dentry — Linux `DCACHE_MOUNTED`. A single
/// REFCOUNTED hint bit (set when the dentry's `struct mountpoint` `m_count`
/// goes 0→1 in [`crate::mntns::get_mountpoint`], cleared on the last drop in
/// [`crate::mntns::put_mountpoint`]) that lets the path walk skip the mount
/// hash for the overwhelmingly common non-mountpoint dentry. ns-AGNOSTIC: the
/// per-ns covering identity comes from the mount hash keyed by the walk's
/// current `mnt_id`, not from this bit. Bit position is this file's own layout.
pub const D_MOUNTED:     u32 = 0x0001_0000;

// ---------------------------------------------------------------------------
// DCACHE_OP_* — `d_op` presence cache, stamped into `d_flags` at construction
// from the inherited `d_op` vector (Linux `d_set_d_op`). Each bit records that
// the corresponding `d_op` hook is non-NULL so the hot path can branch on a
// `d_flags` bit WITHOUT dereferencing `d_op` and probing the `Option` hook:
// `__d_lookup` tests `parent->d_flags & DCACHE_OP_COMPARE` before calling
// `d_compare`; `dput`/`dentry_kill` test `DCACHE_OP_DELETE` before `d_delete`.
// Bit positions are this file's own layout (the rest of `d_flags` already
// diverges from Linux's numeric bits — see the `D_ROOT..D_DISCONNECTED` block).
// Every dcache-exposed hook gets a presence bit; the only `dentry_operations`
// members WITHOUT a hook here are the mount-trigger pair (`d_automount`/
// `d_manage`, mount-coupled) and overlayfs `d_real`.
// ---------------------------------------------------------------------------
/// `d_op->d_hash` present (Linux `DCACHE_OP_HASH`).
pub const D_OP_HASH:       u32 = 0x0040;
/// `d_op->d_compare` present (Linux `DCACHE_OP_COMPARE`).
pub const D_OP_COMPARE:    u32 = 0x0080;
/// `d_op->d_revalidate` present (Linux `DCACHE_OP_REVALIDATE`).
pub const D_OP_REVALIDATE: u32 = 0x0100;
/// `d_op->d_delete` present (Linux `DCACHE_OP_DELETE`).
pub const D_OP_DELETE:     u32 = 0x0200;
/// `d_op->d_dname` present (Linux `DCACHE_OP_DNAME`) — the dentry renders its
/// OWN path string dynamically (pipefs `pipe:[ino]`, sockfs `socket:[ino]`,
/// anon-inode `[name]`), so `d_path`/`dentry_path` must NOT parent-walk it.
pub const D_OP_DNAME:      u32 = 0x0400;
/// `d_op->d_prune` present (Linux `DCACHE_OP_PRUNE`). `__dentry_kill` tests
/// this bit before firing `d_prune` on a dentry about to leave the cache, so
/// the eviction hot path skips the `d_op` deref for the common no-prune fs.
pub const D_OP_PRUNE:      u32 = 0x0800;
/// `d_op->d_weak_revalidate` present (Linux `DCACHE_OP_WEAK_REVALIDATE`).
/// `complete_walk` tests this on the FINAL path component (post-jump, e.g. a
/// `..`/procfs-symlink hop that changed mount) before the one-shot weak
/// revalidation, so the check stays off the per-component hot path.
pub const D_OP_WEAK_REVALIDATE: u32 = 0x2000;
/// All `d_op` presence bits (cleared together before a re-stamp).
pub const D_OP_MASK: u32 = D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE | D_OP_DNAME | D_OP_PRUNE | D_OP_WEAK_REVALIDATE;

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

// ---------------------------------------------------------------------------
// DCACHE_ENTRY_TYPE — cached inode type, stamped into `d_flags` the moment an
// inode is associated (`build` / `set_inode`). Linux keeps these so the hot
// path (`d_is_dir` in the walker, `d_is_symlink` before a symlink follow)
// branches on the dentry WITHOUT read-locking + dereferencing `d_inode`.
// Layout mirrors Linux `include/linux/dcache.h`: the type occupies bits 20..22
// (`7 << 20`), `MISS == 0` so a negative dentry's type field is naturally clear.
// ---------------------------------------------------------------------------
/// Mask selecting the cached-type field (Linux `DCACHE_ENTRY_TYPE`).
pub const D_TYPE_MASK:      u32 = 0x0070_0000;
/// Negative dentry — no inode (Linux `DCACHE_MISS_TYPE`).
pub const D_MISS_TYPE:      u32 = 0x0000_0000;
/// Directory (Linux `DCACHE_DIRECTORY_TYPE`).
pub const D_DIRECTORY_TYPE: u32 = 0x0020_0000;
/// Regular file (Linux `DCACHE_REGULAR_TYPE`).
pub const D_REGULAR_TYPE:   u32 = 0x0040_0000;
/// char/block/fifo/socket (Linux `DCACHE_SPECIAL_TYPE`).
pub const D_SPECIAL_TYPE:   u32 = 0x0050_0000;
/// Symlink (Linux `DCACHE_SYMLINK_TYPE`).
pub const D_SYMLINK_TYPE:   u32 = 0x0060_0000;

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

// ---------------------------------------------------------------------------
// QStr — Linux `struct qstr`: name + precomputed `full_name_hash` (`16§96`).
// ---------------------------------------------------------------------------

/// Max name length stored inline in the dentry (Linux `DNAME_INLINE_LEN`,
/// 32 on 64-bit). Names `<=` this avoid the per-dentry heap allocation.
pub const DNAME_INLINE_LEN: usize = 32;

/// Name storage backing a `QStr`: inline UTF-8 bytes (Linux `d_iname`) for
/// short names, external `String` (Linux `d_name.name`) for long names.
/// `Inline.buf[..len]` always holds the bytes of a once-valid `&str`.
enum DName { Inline { buf: [u8; DNAME_INLINE_LEN], len: u8 }, Heap(String) }

/// Hashed path component. `hash` is `full_name_hash(parent, name)` so the
/// same name under different parents lands in different hash buckets and
/// `d_op->d_hash` can fold case before hashing.
pub struct QStr {
    hash: u32,
    name: DName,
}

impl QStr {
    /// # C: O(name.len())
    pub fn new(parent: Option<&Arc<Dentry>>, name: &str) -> Self {
        let hash = Dentry::compute_hash(parent, name);
        let b = name.as_bytes();
        let name = if b.len() <= DNAME_INLINE_LEN {
            let mut buf = [0u8; DNAME_INLINE_LEN];
            buf[..b.len()].copy_from_slice(b);
            DName::Inline { buf, len: b.len() as u8 }
        } else { DName::Heap(String::from(name)) };
        QStr { hash, name }
    }
    /// # C: O(1)
    pub fn hash(&self) -> u32 { self.hash }
    /// # C: O(1)
    pub fn name(&self) -> &str {
        match &self.name {
            // Bytes were copied from a valid `&str` in `new`; checked decode
            // can never fail, `unwrap_or` keeps it unsafe-free.
            DName::Inline { buf, len } => core::str::from_utf8(&buf[..*len as usize]).unwrap_or(""),
            DName::Heap(s) => s,
        }
    }
    /// Test probe: is the name stored inline (not heap)? # C: O(1)
    #[doc(hidden)]
    pub fn is_inline(&self) -> bool { matches!(self.name, DName::Inline { .. }) }
}

// ---------------------------------------------------------------------------
// Lockref — Linux `d_count`. This is the VFS-visible pin count, NOT the
// memory-reclaim trigger. Rust `Arc` already gives safe reclaim; `d_count`
// is the LRU/shrinker accounting + the "in active use" gate. `d_count==0`
// means "unused, eligible for the LRU/shrinker" — it is NOT "free now".
// (Linux `CONFIG_ARCH_USE_CMPXCHG_LOCKREF=n` path: spinlock-guarded i64;
// we model it with a single atomic, semantics identical, atomic fast-path
// is the obvious later optimization.)
// ---------------------------------------------------------------------------

/// Sentinel `d_count` for a dentry whose kill is in progress (Linux
/// `LOCKREF_DEAD`, `lib/lockref.c`). A dead lockref is `< 0`, so every
/// `get_not_dead` / `get_not_zero` resurrection attempt fails and a concurrent
/// `__d_lookup_rcu` skips a dentry mid-`__dentry_kill`. Value matches Linux.
pub const LOCKREF_DEAD: i64 = -128;

pub struct Lockref {
    count: AtomicI64,
}

impl Lockref {
    /// # C: O(1)
    const fn new() -> Self { Lockref { count: AtomicI64::new(0) } }
    /// `lockref_get`. # C: O(1)
    pub fn get(&self) -> i64 { self.count.fetch_add(1, Ordering::AcqRel) + 1 }
    /// `lockref_put_return`. # C: O(1)
    pub fn put(&self) -> i64 { self.count.fetch_sub(1, Ordering::AcqRel) - 1 }
    /// # C: O(1)
    pub fn read(&self) -> i64 { self.count.load(Ordering::Acquire) }

    /// `lockref_get_not_zero`: pin only a currently-pinned ref (count `> 0`),
    /// returning false when the count is 0 (unused — on the LRU/shrinker) or
    /// dead. Distinct from `get_not_dead`: this REFUSES to resurrect a count-0
    /// dentry. CAS retry loop models Linux's `CMPXCHG_LOOP`. # C: O(1) amortized
    pub fn get_not_zero(&self) -> bool {
        let mut old = self.count.load(Ordering::Acquire);
        loop {
            if old <= 0 { return false; }
            match self.count.compare_exchange_weak(old, old + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_)    => return true,
                Err(cur) => old = cur,
            }
        }
    }

    /// `lockref_get_not_dead`: pin unless the ref is being killed (count `< 0`,
    /// i.e. `LOCKREF_DEAD`). Unlike `get_not_zero` this DOES resurrect a count-0
    /// (unused) ref — exactly Linux `__d_lookup_rcu`, which legitimately
    /// re-pins an LRU dentry but must never grab one mid-`__dentry_kill`.
    /// # C: O(1) amortized
    pub fn get_not_dead(&self) -> bool {
        let mut old = self.count.load(Ordering::Acquire);
        loop {
            if old < 0 { return false; }
            match self.count.compare_exchange_weak(old, old + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_)    => return true,
                Err(cur) => old = cur,
            }
        }
    }

    /// `lockref_mark_dead`: stamp the kill sentinel (`LOCKREF_DEAD`). Linux does
    /// this under `d_lock` at the top of `__dentry_kill`, after which no `get`
    /// can resurrect the ref. # C: O(1)
    pub fn mark_dead(&self) { self.count.store(LOCKREF_DEAD, Ordering::Release); }

    /// True iff the lockref is dead (`< 0`) — kill in progress. # C: O(1)
    pub fn is_dead(&self) -> bool { self.count.load(Ordering::Acquire) < 0 }
}

// ---------------------------------------------------------------------------
// DentryOps — Linux `dentry_operations`. All `'static` fn ptrs (no `dyn`,
// honors the HAL no-dyn rule `07§5`). `None` per-hook = default behavior
// (byte-exact compare, hash-as-stored), so `d_op == None` is zero
// regression vs the pre-B3 dcache.
// ---------------------------------------------------------------------------

/// `d_hash`: hash the name portion (parent salt is folded in by the VFS).
/// Override to case-fold (return the hash of the normalized name).
pub type DHashFn = fn(name: &str) -> u32;
/// `d_compare`: true iff `name` matches the cached dentry `cand` (case-fold,
/// unicode-normalize, …). Default = byte-exact `cand.name() == name`.
pub type DCompareFn = fn(name: &str, cand: &Dentry) -> bool;
/// `d_revalidate`: false ⇒ the cached dentry is stale, drop + slow-path.
/// `reval` carries Linux `LOOKUP_REVAL` (the ESTALE-retry / forced
/// revalidation flag): a fs that trusts an attribute-cache timeout on the
/// ordinary walk must re-check against its backing store when `reval` is set
/// (NFS/FUSE/AFS `flags & LOOKUP_REVAL`).
pub type DRevalidateFn = fn(d: &Arc<Dentry>, reval: bool) -> bool;
/// `d_weak_revalidate`: the one-shot weak counterpart of `d_revalidate`,
/// invoked by Linux `complete_walk` on the FINAL resolved dentry when the walk
/// reached it via a jump (`..` out of a mount, a procfs magic symlink) rather
/// than a per-component `d_revalidate`. `false` ⇒ the result is stale (Linux
/// returns `-ESTALE` → the caller retries with `LOOKUP_REVAL`); UNLIKE
/// `d_revalidate` the dentry is NOT dropped here — it remains a valid cache node,
/// only this resolution is rejected. `reval` threads `LOOKUP_REVAL`.
pub type DWeakRevalidateFn = fn(d: &Arc<Dentry>, reval: bool) -> bool;
/// `d_delete`: true ⇒ on final `dput` free immediately (don't LRU-cache).
pub type DDeleteFn = fn(d: &Dentry) -> bool;
/// `d_release`: dentry is being freed (final `Arc` drop).
pub type DReleaseFn = fn(d: &Dentry);
/// `d_iput`: an inode is being disassociated from the dentry.
pub type DIputFn = fn(d: &Dentry, inode: InodeRef);
/// `d_dname`: render this dentry's path string dynamically (Linux
/// `dentry_operations::d_dname`, e.g. pipefs `pipe:[%lu]`). Set ONLY on
/// `d_alloc_pseudo` dentries; consulted by `d_path`/`dentry_path` in place of
/// the parent walk. Returns the full displayed name (no leading-slash logic —
/// it IS the whole path, like Linux's `dynamic_dname` buffer).
pub type DDnameFn = fn(d: &Dentry) -> String;
/// `d_init`: a dentry has just been allocated for this fs (Linux
/// `dentry_operations::d_init`, fired by `__d_alloc` right after `d_set_d_op`).
/// The fs initializes its per-dentry private state here (typically stamping
/// `d_fsdata`). Infallible in this model — `build` cannot fail — so it returns
/// `()` rather than Linux's `int` ENOMEM path (allocation lives in the fs token,
/// not the dentry).
pub type DInitFn = fn(d: &Dentry);
/// `d_prune`: a dentry is about to be pruned/killed out of the cache (Linux
/// `dentry_operations::d_prune`, fired by `__dentry_kill` before the unhash).
/// The fs drops any cache-side bookkeeping keyed on this dentry. Fires for every
/// eviction route — final `dput`, the LRU / per-sb / subtree shrinkers, and
/// `d_prune_aliases` — since all funnel through `dentry_kill`.
pub type DPruneFn = fn(d: &Dentry);

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
    /// `full_name_hash(parent, name)` (`16§96`). FNV-1a over the bytes,
    /// salted by the parent pointer, with `d_op->d_hash` allowed to replace
    /// the name-portion hash (case-fold). The salt makes the same name under
    /// different parents hash differently; folding the parent in here means
    /// the global table can bucket on `hash` alone. # C: O(name.len())
    pub fn compute_hash(parent: Option<&Arc<Dentry>>, name: &str) -> u32 {
        let salt = match parent { Some(p) => Arc::as_ptr(p) as usize as u64, None => 0 };
        // d_op->d_hash override (parent's ops apply to its children's names).
        let name_hash = match parent.and_then(|p| p.d_op).and_then(|o| o.d_hash) {
            Some(f) => f(name) as u64,
            None    => Self::fnv1a(name.as_bytes()),
        };
        let mut h = salt.wrapping_mul(0x100000001B3) ^ name_hash;
        h ^= h >> 32;
        (h as u32) ^ ((h >> 13) as u32)
    }

    /// FNV-1a 64 over `bytes`. # C: O(bytes.len())
    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes { h = (h ^ b as u64).wrapping_mul(0x100000001B3); }
        h
    }

    /// Shared builder. `sb` is the owning-superblock `Weak` (default
    /// `Weak::new()` for sb-less dentries during the WP6 migration).
    /// # C: O(name.len())
    fn build(parent: Option<Arc<Dentry>>, name: &str, inode: Option<InodeRef>, sb: Weak<SuperBlock>, d_op: Option<&'static DentryOps>, mut flags: u32) -> Arc<Self> {
        if inode.is_none() { flags |= D_NEGATIVE; }
        flags = (flags & !D_TYPE_MASK) | type_bits_for(&inode); // DCACHE_ENTRY_TYPE stamp
        flags = (flags & !D_OP_MASK) | op_flags_for(d_op);      // DCACHE_OP_* stamp (d_set_d_op)
        let qname = QStr::new(parent.as_ref(), name);
        let d = Arc::new(Self {
            parent,
            name: qname,
            inode: RwLock::new(inode),
            sb,
            d_op,
            d_count: Lockref::new(),
            d_flags: AtomicU32::new(flags),
            children: RwLock::new(BTreeMap::new()),
            d_time: AtomicU64::new(0),
            d_fsdata: AtomicU64::new(0),
            d_seq: AtomicU32::new(0),
            counted: AtomicBool::new(false),
        });
        // Linux `__d_alloc`: after `d_set_d_op`, fire `d_op->d_init` so the fs
        // can stamp its per-dentry private state (`d_fsdata`) at allocation.
        if let Some(f) = d_op.and_then(|o| o.d_init) { f(&d); }
        d
    }

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

    /// Construct a positive dentry — name resolves to `inode`. sb-less
    /// (`Weak::new()`); use `new_child` to inherit a parent's superblock.
    /// # C: O(name.len())
    pub fn new(parent: Option<Arc<Dentry>>, name: String, inode: InodeRef) -> Arc<Self> {
        Self::build(parent, &name, Some(inode), Weak::new(), None, 0)
    }

    /// Construct a negative dentry — `name` is known to be absent.
    /// # C: O(name.len())
    pub fn new_negative(parent: Option<Arc<Dentry>>, name: String) -> Arc<Self> {
        Self::build(parent, &name, None, Weak::new(), None, 0)
    }

    /// Construct a free-floating root dentry. No parent; inode required.
    /// # C: O(1)
    pub fn new_root(inode: InodeRef) -> Arc<Self> {
        Self::build(None, "", Some(inode), Weak::new(), None, D_ROOT)
    }

    /// Construct a child dentry under `parent`, inheriting `parent.d_sb` and
    /// `parent.d_op`. `inode == None` builds a negative dentry. This is how
    /// the dcache primitives (`d_alloc`/`d_add`) propagate the superblock +
    /// ops down the tree. # C: O(name.len())
    pub fn new_child(parent: &Arc<Dentry>, name: &str, inode: Option<InodeRef>) -> Arc<Self> {
        Self::build(Some(parent.clone()), name, inode, parent.sb.clone(), parent.d_op, 0)
    }

    /// Construct a superblock root dentry whose `d_sb` points at `sb`
    /// (Linux `d_make_root`). # C: O(1)
    pub fn new_root_in_sb(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Self> {
        Self::build(None, "", Some(inode), Arc::downgrade(sb), None, D_ROOT)
    }

    /// Construct an ANONYMOUS disconnected dentry (Linux `__d_obtain_alias`
    /// → `__d_alloc(sb, &anonstring)` with the "/" name + `DCACHE_DISCONNECTED`).
    /// Parentless, positive, flagged `D_DISCONNECTED`; NOT a superblock root
    /// (`D_ROOT` stays clear). `d_sb` is the inode's owning SB if it has one.
    /// # C: O(1)
    pub fn new_anon(inode: InodeRef) -> Arc<Self> {
        let sb = match inode.i_sb() { Some(s) => Arc::downgrade(&s), None => Weak::new() };
        Self::build(None, "/", Some(inode), sb, None, D_DISCONNECTED)
    }

    /// Construct a PSEUDO dentry (Linux `d_alloc_pseudo`): a parentless,
    /// positive dentry carrying a `d_op` whose `d_dname` renders the displayed
    /// path dynamically (pipefs `pipe:[ino]`, sockfs `socket:[ino]`, anon-inode
    /// `[eventfd]`). `name` is the static fallback `d_name` (Linux keeps it for
    /// the rare no-`d_dname` reader); the live path comes from `d_op->d_dname`.
    /// NOT hashed and NOT a superblock root — these never participate in the
    /// (parent,name) lookup table. # C: O(name.len())
    pub fn new_pseudo(name: &str, inode: InodeRef, d_op: &'static DentryOps) -> Arc<Self> {
        let sb = match inode.i_sb() { Some(s) => Arc::downgrade(&s), None => Weak::new() };
        Self::build(None, name, Some(inode), sb, Some(d_op), 0)
    }

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

    /// Absolute (GLOBAL) path for this dentry — Linux `d_path` / `prepend_path`:
    /// walk the parent chain to the global root and join `d_name`s with `/`,
    /// CROSSING mount boundaries. After the namei keystone (`__follow_mount`) a
    /// dentry resolved inside a mount is parented under that mount's `s_root`
    /// (parentless `D_ROOT`), NOT under the covered underlay; a pure parent walk
    /// would therefore collapse `/dev/null` to `/null`. So at each parentless
    /// mounted-fs root we bridge to the mount's mountpoint dentry in the parent
    /// mount (`mount::mountpoint_for_root_ptr`) and continue — exactly what
    /// Linux `prepend_path` does with `mnt_mountpoint`.
    ///
    /// Used by `/proc/<pid>/fd/N` readlink + `execveat(fd, "", AT_EMPTY_PATH)`
    /// + mountinfo source rendering. Returns `b"/"` for the root dentry;
    /// otherwise `b"/sbin/init"`. Empty-named roots contribute no slash so we
    /// never emit `//sbin/init`. # C: O(depth × N_mounts)
    pub fn absolute_path(&self) -> Vec<u8> {
        // Pseudo dentries (`d_alloc_pseudo`) render their own path via
        // `d_op->d_dname` (Linux `prepend_path`: `if (dentry->d_op &&
        // dentry->d_op->d_dname) return dentry->d_op->d_dname(...)`) — never
        // parent-walk a `pipe:[ino]`/`[eventfd]` into a bogus `/eventfd`.
        if let Some(dyn_name) = self.d_dname() { return dyn_name.into_bytes(); }
        let mut parts: Vec<String> = Vec::new();
        if !self.name.name().is_empty() { parts.push(String::from(self.name.name())); }
        // First ancestor: `d_parent`, or — if this dentry is itself a mounted
        // fs root — the mountpoint it covers.
        let mut cur: Option<Arc<Dentry>> = match self.parent.clone() {
            Some(p) => Some(p),
            None if self.is_root() => crate::mount::mountpoint_for_root_ptr(self as *const Dentry),
            None => None,
        };
        while let Some(d) = cur {
            if !d.name.name().is_empty() { parts.push(String::from(d.name.name())); }
            cur = match d.parent.clone() {
                Some(p) => Some(p),
                None if d.is_root() => crate::mount::mountpoint_for_root_ptr(Arc::as_ptr(&d)),
                None => None,
            };
        }
        if parts.is_empty() { return alloc::vec![b'/']; }
        let mut out: Vec<u8> = Vec::new();
        for name in parts.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(name.as_bytes());
        }
        out
    }

    /// Filesystem-internal path string for this dentry — Linux `__dentry_path`
    /// / `dentry_path_raw` (`fs/d_path.c`): walk the `d_parent` chain toward the
    /// root, prepending each `d_name`, and STOP the instant the cursor reaches
    /// `root` (when supplied) or a filesystem root (`D_ROOT` / parentless). The
    /// stop dentry's own name is NOT prepended — the leading "/" stands in for
    /// it, so the root walk renders "/".
    ///
    /// Unlike `absolute_path` this does NOT cross mount boundaries: it is the
    /// within-one-superblock reconstructor that `getcwd`, `/proc/<pid>/fd/N`
    /// readlink, and the `/proc/<pid>/maps` path column build on relative to a
    /// known root. An unlinked-but-open dentry (`is_unlinked`) or an anonymous
    /// `D_DISCONNECTED` alias is unreachable from any root, so the result is
    /// suffixed " (deleted)" exactly as Linux `dentry_path_raw` marks it.
    /// # C: O(depth)
    pub fn dentry_path(&self, root: Option<&Arc<Dentry>>) -> String {
        // Pseudo dentries render their own name (Linux `__dentry_path` defers to
        // `d_dname` for these) — return it verbatim, no parent walk / "(deleted)".
        if let Some(dyn_name) = self.d_dname() { return dyn_name; }
        let root_ptr = root.map(Arc::as_ptr);
        let me_ptr = self as *const Dentry;
        let mut parts: Vec<String> = Vec::new();
        // The start dentry contributes its name only when it is neither the
        // stop `root` nor a tree terminus (`D_ROOT` / disconnected). A terminus
        // start yields no components → "/".
        if root_ptr != Some(me_ptr) && !self.is_root() && !self.is_disconnected() {
            if !self.name().is_empty() { parts.push(String::from(self.name())); }
            let mut cur = self.parent.clone();
            while let Some(d) = cur {
                if root_ptr == Some(Arc::as_ptr(&d)) || d.is_root() || d.is_disconnected() { break; }
                if !d.name().is_empty() { parts.push(String::from(d.name())); }
                cur = d.parent.clone();
            }
        }
        let mut out = String::new();
        if parts.is_empty() { out.push('/'); }
        else { for name in parts.iter().rev() { out.push('/'); out.push_str(name); } }
        if self.is_unlinked() || self.is_disconnected() { out.push_str(" (deleted)"); }
        out
    }
}

impl Drop for Dentry {
    /// Fire `d_op->d_release` on the final free (Linux `d_release`). The
    /// `Arc` strong count reaching zero IS the free; `d_count`/LRU only gate
    /// when that becomes possible. # C: O(1)
    //
    // D12 (RCU-grace deferred free): Linux defers the dentry reclaim tail
    // (`__d_free` / `dentry_iput`) to `call_rcu(&dentry->d_rcu, …)` so the
    // final free lands only after an RCU grace period — past the window a
    // lock-free `__d_lookup_rcu` reader could still hold a reference. We now
    // route the reclaim (the counted `i_count` release — the "free" side of
    // this dentry's inode hold) through `sync::call_rcu` (grace machinery in
    // `sync::rcu`, QS driven by the scheduler ctxsw/idle, drained by
    // `ksoftirqd` + the timer tick). The `d_release` callback stays SYNCHRONOUS
    // — it needs a live `&self`, and Linux likewise runs `d_op->d_release` in
    // `__dentry_kill` before the `call_rcu(__d_free)` tail.
    //
    // Safety of the deferral: the closure OWNS the `InodeRef` (`Arc<Inode>`),
    // keeping the inode alive until it runs; `dentry_iput` re-derives the SB
    // through the inode's WEAK `i_sb` at run time (falling back to a plain
    // `i_count_dec` if the SB is already gone), so it never delays SB teardown
    // and never UAFs. Leak-safety: `call_rcu`'s high-water mark + the
    // ksoftirqd/tick drain guarantee the closure always runs. The Arc/Weak
    // reader is unchanged (`dcache.rs` `lookup_rcu` stays `Weak::upgrade`), so
    // this deferral is Linux-FIDELITY for the reclaim timing; the raw-pointer
    // rcu-walk reader that would consume the grace for safety is SMP-gated
    // (ledger D3). See ledger D12.
    fn drop(&mut self) {
        // d_release first, while `self` is still live (Linux __dentry_kill).
        if let Some(f) = self.d_op.and_then(|o| o.d_release) { f(self); }
        // D3/D37: release this dentry's counted `i_count` hold on its inode
        // (Linux `dentry_iput`), exactly once and only when `grab_inode_hold`
        // took one. A `set_inode(None)` (d_delete) that already released it
        // leaves `counted == false`, so this never double-iputs. D12: the
        // release is now deferred past an RCU grace period via `call_rcu`.
        if self.counted.swap(false, Ordering::AcqRel) {
            let held = { let mut g = self.inode.write(); g.take() };
            if let Some(inode) = held {
                sync::call_rcu(alloc::boxed::Box::new(move || dentry_iput(inode)));
            }
        }
    }
}

/// Release one dentry-held `i_count` reference (Linux `iput`, reached via
/// `dentry_iput`). A superblock-backed inode routes through [`SuperBlock::iput`]
/// so a 1→0 drop runs the `drop_inode`/`evict_inode` lifecycle; an anon inode
/// (no SB / icache: pipe/eventfd/socket/…) balances the count in place. Mirrors
/// `File::drop`'s release, so the two INDEPENDENT counted holds on one inode (an
/// open file description + a dentry alias) are each balanced and neither
/// underflows. # C: O(log N_ino) for an SB inode, else O(1)
fn dentry_iput(inode: InodeRef) {
    match inode.i_sb() {
        Some(sb) => sb.iput(inode),
        None     => { inode.i_count_dec(); }
    }
}
