// Dentry per `16§2`. Holds parent / name / cached inode pointer.
// Negative dentries (`inode == None`) cache "name not found" results
// per `16§4` so repeated path lookups don't re-walk the FS.
//
// Cache structure (`16§4`: open-addressed hash, RCU read) lands with
// the cache impl PR; this PR provides the dentry node only.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use sync::{Dentry as DentryClass, Inode as InodeClass, RwLock};

use crate::inode::InodeRef;

/// Single path-component cache node.
pub struct Dentry {
    parent: Option<Arc<Dentry>>,
    name:   String,
    inode:  RwLock<Option<InodeRef>, InodeClass>,
    /// Resolved children by component name (`16§4` dentry cache). A
    /// per-dentry map rather than the global open-addressed hash the
    /// spec describes — same invariants, simpler; the global hash + RCU
    /// is a perf follow-up. Lock class `Dentry` (`06§3.6`).
    children: RwLock<BTreeMap<String, Arc<Dentry>>, DentryClass>,
    /// Namespace-scoped mount link. Linux mount crossing is not a property
    /// of a dentry alone: the same dentry can be covered differently in
    /// different mount namespaces. This table records the covering mount id
    /// for each namespace. The mount table, not the dentry, owns the mounted
    /// filesystem/root object.
    mounted_mounts: RwLock<BTreeMap<u64, u64>, DentryClass>,
}

impl Dentry {
    /// Construct a positive dentry — name resolves to `inode`.
    /// # C: O(1)
    pub fn new(parent: Option<Arc<Dentry>>, name: String, inode: InodeRef) -> Arc<Self> {
        Arc::new(Self {
            parent,
            name,
            inode: RwLock::new(Some(inode)),
            children: RwLock::new(BTreeMap::new()),
            mounted_mounts: RwLock::new(BTreeMap::new()),
        })
    }

    /// Construct a negative dentry — `name` is known to be absent.
    /// # C: O(1)
    pub fn new_negative(parent: Option<Arc<Dentry>>, name: String) -> Arc<Self> {
        Arc::new(Self {
            parent,
            name,
            inode: RwLock::new(None),
            children: RwLock::new(BTreeMap::new()),
            mounted_mounts: RwLock::new(BTreeMap::new()),
        })
    }

    /// Construct a free-floating root dentry. No parent; inode required.
    /// # C: O(1)
    pub fn new_root(inode: InodeRef) -> Arc<Self> {
        Self::new(None, String::new(), inode)
    }

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
        *self.inode.write() = inode;
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

    /// Absolute path for this dentry — walk the parent chain to the
    /// root and join names with `/`. Used by `/proc/<pid>/fd/N`
    /// readlink + by `execveat(fd, "", AT_EMPTY_PATH)` to materialise
    /// the path of an open file descriptor.
    ///
    /// Returns `b"/"` for the root dentry; otherwise an absolute path
    /// like `b"/sbin/init"`. Empty-named ancestors (the root sentinel)
    /// don't contribute a slash so we don't emit `//sbin/init`. If a
    /// dentry's `name` already contains slashes (the legacy
    /// `install_open` path stores the entire pathname in a single
    /// dentry with no parent), that name is returned as-is —
    /// guarding against `//dev/pts/3` from `b"/" + name`.
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
        // Single-component dentry whose name already encodes an
        // absolute path (install_open shape today). Return verbatim.
        if parts.len() == 1 && parts[0].as_bytes().first() == Some(&b'/') {
            return parts[0].as_bytes().to_vec();
        }
        let mut out: Vec<u8> = Vec::new();
        for name in parts.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(name.as_bytes());
        }
        out
    }
}
