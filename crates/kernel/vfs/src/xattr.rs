// Per-inode xattr STORAGE backend (Linux `simple_xattrs` / the `i_op` xattr
// family). The authority for extended attributes is the OWNING filesystem's
// per-inode store, NOT a global table: each inode that supports xattrs carries
// a [`SimpleXattrs`] (a name→value map under the inode's own lock), reached
// through the `i_op->{get,set,remove,list}xattr` hooks on [`crate::InodeOps`].
//
// The VFS-layer policy (namespace permission, name/size limits, the
// XATTR_CREATE/XATTR_REPLACE meaning) lives in the syscall layer (`fs::xattr`),
// mirroring Linux `vfs_setxattr` → `xattr_permission` → `handler->set`. This
// module owns only STORAGE + the atomic flag check.
//
// Backends that own no xattr store (procfs/sysfs/devfs/…) leave the inode's
// `i_xattrs` field `None`; their `i_op` xattr ops return [`XattrError::NotSup`]
// so the caller can apply the legacy fallback / report `EOPNOTSUPP`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sync::{Inode as InodeLockClass, Spinlock};

/// Xattr backend error — the three Linux xattr-storage outcomes that are not a
/// plain success. Distinct from [`crate::VfsError`] because `ENODATA` (61) has
/// no VfsError variant; the syscall layer maps these to the raw xattr errnos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrError {
    /// `ENODATA` — the named attribute does not exist (get/remove, or
    /// `XATTR_REPLACE` set of an absent name).
    NotFound,
    /// `EEXIST` — `XATTR_CREATE` set of a name that already exists.
    Exists,
    /// `EOPNOTSUPP` — this inode's filesystem has no xattr store.
    NotSup,
}

/// `simple_xattrs` (Linux `fs/xattr.c`) — a per-inode name→value map under the
/// inode's own lock (rank `Inode`, 40). Embedded in an inode's `i_xattrs`, so
/// the store is OWNED by the inode object and dies with it — no global table,
/// no cross-fs leakage. # C: O(log N) per op
pub struct SimpleXattrs {
    map: Spinlock<BTreeMap<String, Vec<u8>>, InodeLockClass>,
}

impl Default for SimpleXattrs {
    fn default() -> Self { Self::new() }
}

impl SimpleXattrs {
    /// An empty store. # C: O(1)
    pub fn new() -> Self { Self { map: Spinlock::new(BTreeMap::new()) } }

    /// Value bytes for `name`, or `None` if absent. # C: O(log N)
    pub fn get(&self, name: &str) -> Option<Vec<u8>> {
        self.map.lock().get(name).cloned()
    }

    /// Set `name`→`value`, honouring the Linux flag semantics ATOMICALLY under
    /// the store lock: `create` (XATTR_CREATE) fails `Exists` if the name is
    /// present; `replace` (XATTR_REPLACE) fails `NotFound` if it is absent.
    /// # C: O(log N)
    pub fn set(&self, name: &str, value: Vec<u8>, create: bool, replace: bool) -> Result<(), XattrError> {
        let mut g = self.map.lock();
        let exists = g.contains_key(name);
        if create && exists { return Err(XattrError::Exists); }
        if replace && !exists { return Err(XattrError::NotFound); }
        g.insert(name.to_string(), value);
        Ok(())
    }

    /// Remove `name`; `NotFound` if absent. # C: O(log N)
    pub fn remove(&self, name: &str) -> Result<(), XattrError> {
        if self.map.lock().remove(name).is_some() { Ok(()) } else { Err(XattrError::NotFound) }
    }

    /// All attribute names (for listxattr). # C: O(N)
    pub fn list_names(&self) -> Vec<String> {
        self.map.lock().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrip_and_flags() {
        let x = SimpleXattrs::new();
        // plain set/get
        assert_eq!(x.set("user.a", b"1".to_vec(), false, false), Ok(()));
        assert_eq!(x.get("user.a"), Some(b"1".to_vec()));
        assert_eq!(x.get("user.z"), None);
        // XATTR_CREATE on an existing name → Exists; XATTR_REPLACE absent → NotFound.
        assert_eq!(x.set("user.a", b"2".to_vec(), true, false), Err(XattrError::Exists));
        assert_eq!(x.set("user.b", b"2".to_vec(), false, true), Err(XattrError::NotFound));
        // list + remove
        let mut names = x.list_names();
        names.sort();
        assert_eq!(names, alloc::vec![String::from("user.a")]);
        assert_eq!(x.remove("user.a"), Ok(()));
        assert_eq!(x.remove("user.a"), Err(XattrError::NotFound));
        assert!(x.list_names().is_empty());
    }
}
