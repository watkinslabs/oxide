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
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

use sync::{Dentry as DentryClass, Inode as InodeClass, RwLock};

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

/// `d_flags` bits (Linux `include/linux/dcache.h` subset).
pub const D_ROOT:       u32 = 0x0001; // this dentry is a superblock root
pub const D_NEGATIVE:   u32 = 0x0002; // d_inode == None
pub const D_HASHED:     u32 = 0x0004; // present in the global dentry_hashtable
pub const D_REFERENCED: u32 = 0x0008; // recently used — LRU two-hand-clock bit
pub const D_LRU:        u32 = 0x0010; // currently linked on the dcache LRU

// ---------------------------------------------------------------------------
// QStr — Linux `struct qstr`: name + precomputed `full_name_hash` (`16§96`).
// ---------------------------------------------------------------------------

/// Hashed path component. `hash` is `full_name_hash(parent, name)` so the
/// same name under different parents lands in different hash buckets and
/// `d_op->d_hash` can fold case before hashing.
pub struct QStr {
    hash: u32,
    name: String,
}

impl QStr {
    /// # C: O(name.len())
    pub fn new(parent: Option<&Arc<Dentry>>, name: &str) -> Self {
        QStr { hash: Dentry::compute_hash(parent, name), name: String::from(name) }
    }
    /// # C: O(1)
    pub fn hash(&self) -> u32 { self.hash }
    /// # C: O(1)
    pub fn name(&self) -> &str { &self.name }
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
pub type DRevalidateFn = fn(d: &Arc<Dentry>) -> bool;
/// `d_delete`: true ⇒ on final `dput` free immediately (don't LRU-cache).
pub type DDeleteFn = fn(d: &Dentry) -> bool;
/// `d_release`: dentry is being freed (final `Arc` drop).
pub type DReleaseFn = fn(d: &Dentry);
/// `d_iput`: an inode is being disassociated from the dentry.
pub type DIputFn = fn(d: &Dentry, inode: InodeRef);

pub struct DentryOps {
    pub d_hash:       Option<DHashFn>,
    pub d_compare:    Option<DCompareFn>,
    pub d_revalidate: Option<DRevalidateFn>,
    pub d_delete:     Option<DDeleteFn>,
    pub d_release:    Option<DReleaseFn>,
    pub d_iput:       Option<DIputFn>,
}

impl DentryOps {
    /// All-default ops vector. # C: O(1)
    pub const fn empty() -> Self {
        DentryOps { d_hash: None, d_compare: None, d_revalidate: None, d_delete: None, d_release: None, d_iput: None }
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
    /// Namespace-scoped mount link. Linux mount crossing is not a property
    /// of a dentry alone: the same dentry can be covered differently in
    /// different mount namespaces. This table records the covering mount id
    /// for each namespace. The mount table, not the dentry, owns the mounted
    /// filesystem/root object.
    mounted_mounts: RwLock<BTreeMap<u64, u64>, DentryClass>,
    /// `d_time` — fs-private revalidation stamp (Linux `d_time`). The owning fs
    /// sets it in lookup/`d_revalidate` (a version/generation); the VFS only
    /// stores it. Atomic — a dentry is shared via `Arc`. # consumers: d_revalidate.
    d_time: AtomicU64,
    /// `d_fsdata` — fs-private per-dentry token (Linux `d_fsdata` void*). A
    /// pointer-sized opaque value the owning fs interprets (`0` = unset).
    d_fsdata: AtomicU64,
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
        let qname = QStr::new(parent.as_ref(), name);
        Arc::new(Self {
            parent,
            name: qname,
            inode: RwLock::new(inode),
            sb,
            d_op,
            d_count: Lockref::new(),
            d_flags: AtomicU32::new(flags),
            children: RwLock::new(BTreeMap::new()),
            mounted_mounts: RwLock::new(BTreeMap::new()),
            d_time: AtomicU64::new(0),
            d_fsdata: AtomicU64::new(0),
        })
    }

    /// `d_time` — fs-private revalidation stamp (Linux `d_time`). # C: O(1)
    pub fn d_time(&self) -> u64 { self.d_time.load(Ordering::Acquire) }
    /// Set `d_time` (owning fs, in lookup/`d_revalidate`). # C: O(1)
    pub fn set_d_time(&self, v: u64) { self.d_time.store(v, Ordering::Release); }
    /// `d_fsdata` — fs-private per-dentry token (`0` = unset). # C: O(1)
    pub fn d_fsdata(&self) -> u64 { self.d_fsdata.load(Ordering::Acquire) }
    /// Set `d_fsdata` (owning fs). # C: O(1)
    pub fn set_d_fsdata(&self, v: u64) { self.d_fsdata.store(v, Ordering::Release); }

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

    /// `d_sb` — owning superblock, if any. # C: O(1)
    pub fn d_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }

    /// `d_op` — per-dentry operation vector, if any. # C: O(1)
    pub fn d_op(&self) -> Option<&'static DentryOps> { self.d_op }

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

    /// True iff this dentry is a superblock root (`D_ROOT`). # C: O(1)
    pub fn is_root(&self) -> bool { self.flags() & D_ROOT != 0 }

    /// # C: O(1)
    pub fn name(&self) -> &str { self.name.name() }

    /// # C: O(1)
    pub fn parent(&self) -> Option<&Arc<Dentry>> { self.parent.as_ref() }

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
        let old = { let mut g = self.inode.write(); core::mem::replace(&mut *g, inode) };
        if let (Some(old_inode), Some(f)) = (old, self.d_op.and_then(|o| o.d_iput)) {
            f(self, old_inode);
        }
        self.set_flag(D_NEGATIVE, neg);
    }

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

    /// Covering mount id for mount namespace `ns`, if this dentry is a
    /// mountpoint in that namespace. # C: O(log N_ns_coverings)
    pub fn mounted_mount(&self, ns: u64) -> Option<u64> {
        self.mounted_mounts.read().get(&ns).copied()
    }

    /// Install / clear the namespace-scoped covering mount id. This is the
    /// real VFS mount-crossing identity. # C: O(log N_ns_coverings)
    pub fn set_mounted_mount(&self, ns: u64, mnt_id: Option<u64>) {
        let mut mounts = self.mounted_mounts.write();
        if let Some(id) = mnt_id { mounts.insert(ns, id); } else { mounts.remove(&ns); }
    }

    /// True iff a filesystem is mounted on this dentry IN namespace `ns`
    /// (Linux mount crossing is per-mount-namespace: the same dentry can be
    /// covered in one ns and bare in another, so an any-ns test is a cross-ns
    /// false positive). # C: O(log N_ns_coverings)
    pub fn is_mountpoint(&self, ns: u64) -> bool {
        self.mounted_mounts.read().contains_key(&ns)
    }

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
}

impl Drop for Dentry {
    /// Fire `d_op->d_release` on the final free (Linux `d_release`). The
    /// `Arc` strong count reaching zero IS the free; `d_count`/LRU only gate
    /// when that becomes possible. # C: O(1)
    fn drop(&mut self) {
        if let Some(f) = self.d_op.and_then(|o| o.d_release) { f(self); }
    }
}
