// Dentry per `16§2`. Holds parent / name / cached inode pointer.
// Negative dentries (`inode == None`) cache "name not found" results
// per `16§4` so repeated path lookups don't re-walk the FS.
//
// Cache structure (`16§4`: open-addressed hash, RCU read) lands with
// the cache impl PR; this PR provides the dentry node only.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use sync::{Inode as InodeClass, RwLock};

use crate::inode::InodeRef;

/// Single path-component cache node.
pub struct Dentry {
    parent: Option<Arc<Dentry>>,
    name:   String,
    inode:  RwLock<Option<InodeRef>, InodeClass>,
}

impl Dentry {
    /// Construct a positive dentry — name resolves to `inode`.
    /// # C: O(1)
    pub fn new(parent: Option<Arc<Dentry>>, name: String, inode: InodeRef) -> Arc<Self> {
        Arc::new(Self {
            parent,
            name,
            inode: RwLock::new(Some(inode)),
        })
    }

    /// Construct a negative dentry — `name` is known to be absent.
    /// # C: O(1)
    pub fn new_negative(parent: Option<Arc<Dentry>>, name: String) -> Arc<Self> {
        Arc::new(Self {
            parent,
            name,
            inode: RwLock::new(None),
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
}
