// Dentry per `16§2`. Holds parent / name / cached inode pointer.
// Negative dentries (`inode == None`) cache "name not found" results
// per `16§4` so repeated path lookups don't re-walk the FS.
//
// Cache structure (`16§4`: open-addressed hash, RCU read) lands with
// the cache impl PR; this PR provides the dentry node only.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Dentry as DentryClass, Inode as InodeClass, RwLock};

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

/// `d_flags` bits (Linux `include/linux/dcache.h` subset).
pub const D_ROOT:     u32 = 0x0001; // this dentry is a superblock root
pub const D_NEGATIVE: u32 = 0x0002; // d_inode == None
pub const D_HASHED:   u32 = 0x0004; // present in parent.children

/// Single path-component cache node — Linux `struct dentry`. Keyed by
/// `(d_parent, d_name)` via the owning superblock's per-parent hash;
/// NEVER by an absolute path string.
pub struct Dentry {
    /// `d_parent`. None = root / floating.
    parent: Option<Arc<Dentry>>,
    /// `d_name.name` (no precomputed qstr hash yet).
    name:   String,
    /// `d_inode`. None = NEGATIVE dentry (`16§4`).
    inode:  RwLock<Option<InodeRef>, InodeClass>,
    /// `d_sb` — owning superblock backref. NON-owning `Weak`: the SB owns
    /// `s_root` (strong) and outlives every dentry; making this strong
    /// would form an Arc cycle that leaks the tree at umount. Default
    /// `Weak::new()` for dentries built before their fs owns a SuperBlock
    /// (WP6-pending backends, anon-fd factories).
    sb: Weak<SuperBlock>,
    /// `d_flags`.
    d_flags: AtomicU32,
    /// `d_subdirs` / dentry_hashtable analog: resolved children by
    /// component name (`16§4`). Per-(parent,name) — this IS the dcache
    /// key; there is no global path→dentry map. Lock class `Dentry`.
    children: RwLock<BTreeMap<String, Arc<Dentry>>, DentryClass>,
    /// Namespace-scoped mount link. Linux mount crossing is not a property
    /// of a dentry alone: the same dentry can be covered differently in
    /// different mount namespaces. This table records the covering mount id
    /// for each namespace. The mount table, not the dentry, owns the mounted
    /// filesystem/root object.
    mounted_mounts: RwLock<BTreeMap<u64, u64>, DentryClass>,
}

impl Dentry {
    /// Shared builder. `sb` is the owning-superblock `Weak` (default
    /// `Weak::new()` for sb-less dentries during the WP6 migration).
    /// # C: O(1)
    fn build(parent: Option<Arc<Dentry>>, name: String, inode: Option<InodeRef>, sb: Weak<SuperBlock>, mut flags: u32) -> Arc<Self> {
        if inode.is_none() { flags |= D_NEGATIVE; }
        Arc::new(Self {
            parent,
            name,
            inode: RwLock::new(inode),
            sb,
            d_flags: AtomicU32::new(flags),
            children: RwLock::new(BTreeMap::new()),
            mounted_mounts: RwLock::new(BTreeMap::new()),
        })
    }

    /// Construct a positive dentry — name resolves to `inode`. sb-less
    /// (`Weak::new()`); use `new_child` to inherit a parent's superblock.
    /// # C: O(1)
    pub fn new(parent: Option<Arc<Dentry>>, name: String, inode: InodeRef) -> Arc<Self> {
        Self::build(parent, name, Some(inode), Weak::new(), 0)
    }

    /// Construct a negative dentry — `name` is known to be absent.
    /// # C: O(1)
    pub fn new_negative(parent: Option<Arc<Dentry>>, name: String) -> Arc<Self> {
        Self::build(parent, name, None, Weak::new(), 0)
    }

    /// Construct a free-floating root dentry. No parent; inode required.
    /// # C: O(1)
    pub fn new_root(inode: InodeRef) -> Arc<Self> {
        Self::build(None, String::new(), Some(inode), Weak::new(), D_ROOT)
    }

    /// Construct a child dentry under `parent`, inheriting `parent.d_sb`.
    /// `inode == None` builds a negative dentry. This is how the dcache
    /// primitives (`d_alloc`/`d_add`) propagate the superblock down the
    /// tree. # C: O(1)
    pub fn new_child(parent: &Arc<Dentry>, name: &str, inode: Option<InodeRef>) -> Arc<Self> {
        Self::build(Some(parent.clone()), String::from(name), inode, parent.sb.clone(), 0)
    }

    /// Construct a superblock root dentry whose `d_sb` points at `sb`
    /// (Linux `d_make_root`). # C: O(1)
    pub fn new_root_in_sb(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Self> {
        Self::build(None, String::new(), Some(inode), Arc::downgrade(sb), D_ROOT)
    }

    /// `d_sb` — owning superblock, if any. # C: O(1)
    pub fn d_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }

    /// `d_flags` snapshot. # C: O(1)
    pub fn flags(&self) -> u32 { self.d_flags.load(Ordering::Relaxed) }

    /// True iff this dentry is a superblock root (`D_ROOT`). # C: O(1)
    pub fn is_root(&self) -> bool { self.flags() & D_ROOT != 0 }

    /// # C: O(1)
    pub fn name(&self) -> &str { &self.name }

    /// # C: O(1)
    pub fn parent(&self) -> Option<&Arc<Dentry>> { self.parent.as_ref() }

    /// Cached inode, if positive. Read-locks the slot.
    /// # C: O(1)
    pub fn inode(&self) -> Option<InodeRef> {
        self.inode.read().clone()
    }

    /// True iff this is a negative dentry (cached "not found").
    /// # C: O(1)
    pub fn is_negative(&self) -> bool {
        self.inode.read().is_none()
    }

    /// Replace the cached inode (positive ↔ negative transitions on
    /// `create` / `unlink`).
    /// # C: O(1)
    pub fn set_inode(&self, inode: Option<InodeRef>) {
        let neg = inode.is_none();
        *self.inode.write() = inode;
        // Keep D_NEGATIVE consistent (Linux d_instantiate clears it).
        let mut f = self.d_flags.load(Ordering::Relaxed);
        if neg { f |= D_NEGATIVE; } else { f &= !D_NEGATIVE; }
        self.d_flags.store(f, Ordering::Relaxed);
    }

    /// Cached child dentry for `name`, if previously resolved. Brief
    /// read-lock; never held across an `Inode::lookup` (lock order
    /// Inode < Dentry per `06§3.6`).
    /// # C: O(log N_children)
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
    /// dentry isn't reused).
    /// # C: O(log N_children)
    pub fn forget_child(&self, name: &str) {
        self.children.write().remove(name);
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
        if let Some(id) = mnt_id {
            mounts.insert(ns, id);
        } else {
            mounts.remove(&ns);
        }
    }

    /// True iff a filesystem is mounted on this dentry. # C: O(1)
    pub fn is_mountpoint(&self) -> bool {
        !self.mounted_mounts.read().is_empty()
    }

    /// Absolute path for this dentry — Linux `d_path`: walk the parent
    /// chain to the root and join `d_name`s with `/`. Used by
    /// `/proc/<pid>/fd/N` readlink + `execveat(fd, "", AT_EMPTY_PATH)` to
    /// materialise an open fd's pathname. Every dentry is properly
    /// parented (the open path builds a child under the resolved parent —
    /// `file::open_dentry`), so reconstruction is purely the parent walk;
    /// there is no whole-path-in-one-name special case.
    ///
    /// Returns `b"/"` for the root dentry; otherwise `b"/sbin/init"`.
    /// Empty-named ancestors (the root sentinel) contribute no slash so we
    /// never emit `//sbin/init`.
    /// # C: O(depth)
    pub fn absolute_path(&self) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut parts: Vec<&str> = Vec::new();
        if !self.name.is_empty() { parts.push(&self.name); }
        let mut cur = self.parent.as_ref();
        while let Some(p) = cur {
            if !p.name.is_empty() { parts.push(&p.name); }
            cur = p.parent.as_ref();
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
