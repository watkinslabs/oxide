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
// Backends that own no xattr store (procfs/pipefs/…) leave the inode's
// `i_xattrs` slot undeclared; their `i_op` xattr ops return
// [`XattrError::NotSup`] so the caller reports `EOPNOTSUPP`.
//
// Whether a filesystem holds attributes at all is the SUPERBLOCK's property
// (Linux `sb->s_xattr`), not the individual constructor's, and a filesystem
// whose nodes are minted by many unrelated producers can only state it where
// the node JOINS that superblock. [`XattrSlot`] carries that one bit next to
// the storage so the declaration can be made at the join point rather than at
// every `InodeBuilder` call site.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Inode as InodeLockClass, Spinlock};

/// Mount-owned accounting for bytes retained by an inode's simple xattrs.
/// # C: O(1) per reservation
pub trait XattrAccounting: Send + Sync {
    /// Reserve `bytes`, or reject the xattr mutation without changing state.
    fn reserve(&self, bytes: u64) -> Result<(), crate::VfsError>;
    /// Return bytes released by replacement, removal, or inode eviction.
    fn release(&self, bytes: u64);
}

/// Xattr backend error — Linux xattr-storage outcomes that are not a plain
/// success. Distinct from [`crate::VfsError`] because `ENODATA` (61) has no
/// VfsError variant; filesystem backends still report real VFS failures through
/// `Fs` so quota/space errors reach syscall edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrError {
    /// `ENODATA` — the named attribute does not exist (get/remove, or
    /// `XATTR_REPLACE` set of an absent name).
    NotFound,
    /// `EEXIST` — `XATTR_CREATE` set of a name that already exists.
    Exists,
    /// `EOPNOTSUPP` — this inode's filesystem has no xattr store.
    NotSup,
    /// Filesystem-backed failure (`EDQUOT`, `ENOSPC`, `EIO`, ...).
    Fs(crate::VfsError),
}

/// `simple_xattrs` — a per-inode name→value map under the
/// inode's own lock (rank `Inode`, 40). Embedded in an inode's `i_xattrs`, so
/// the store is OWNED by the inode object and dies with it — no global table,
/// no cross-fs leakage. # C: O(log N) per op
pub struct SimpleXattrs {
    map: Spinlock<BTreeMap<String, Vec<u8>>, InodeLockClass>,
}

impl Default for SimpleXattrs {
    fn default() -> Self { Self::new() }
}

/// An inode's `i_xattrs` — the storage plus the one bit that says whether the
/// owning superblock carries an attribute-handler set at all (Linux
/// `sb->s_xattr`). Undeclared reads as "this filesystem cannot hold
/// attributes" (`EOPNOTSUPP`); declared and empty reads as "no such attribute"
/// (`ENODATA`), and the difference is what a caller branches on.
///
/// The storage is present either way and costs no allocation while empty, so
/// [`declare`](Self::declare) can be made AFTER the inode is built — which is
/// the only place a filesystem whose nodes are minted by unrelated driver
/// crates can state the property. # C: O(1)
pub struct XattrSlot {
    declared: AtomicBool,
    store:    SimpleXattrs,
    account:  Spinlock<Option<Arc<dyn XattrAccounting>>, InodeLockClass>,
}

impl XattrSlot {
    /// A slot on a filesystem with no attribute handlers. # C: O(1)
    pub const fn absent() -> Self {
        Self { declared: AtomicBool::new(false), store: SimpleXattrs::empty(), account: Spinlock::new(None) }
    }

    /// A declared slot holding `s` — the builder's `.xattrs(...)` form, used by
    /// a backend that knows its own superblock at construction. # C: O(1)
    pub fn with_store(s: SimpleXattrs) -> Self {
        Self { declared: AtomicBool::new(true), store: s, account: Spinlock::new(None) }
    }

    /// A declared slot with mount-owned accounting. # C: O(1)
    pub fn with_store_accounting(s: SimpleXattrs, account: Arc<dyn XattrAccounting>) -> Self {
        Self { declared: AtomicBool::new(true), store: s, account: Spinlock::new(Some(account)) }
    }

    /// Attach accounting when an inode joins a filesystem after construction.
    /// # C: O(1)
    pub fn attach_accounting(&self, account: Arc<dyn XattrAccounting>) {
        *self.account.lock() = Some(account);
        self.declared.store(true, Ordering::Release);
    }

    /// State that this inode's filesystem holds attributes. Idempotent, and
    /// safe on an inode already published. # C: O(1)
    pub fn declare(&self) { self.declared.store(true, Ordering::Release); }

    /// The store, or `None` on a filesystem with no attribute handlers. # C: O(1)
    pub fn get(&self) -> Option<&SimpleXattrs> {
        if self.declared.load(Ordering::Acquire) { Some(&self.store) } else { None }
    }

    /// Set an attribute and reserve its Linux-shaped storage footprint. # C: O(log N)
    pub fn set(&self, name: &str, value: Vec<u8>, create: bool, replace: bool) -> Result<(), XattrError> {
        if !self.declared.load(Ordering::Acquire) { return Err(XattrError::NotSup); }
        let mut g = self.store.map.lock();
        let exists = g.contains_key(name);
        if create && exists { return Err(XattrError::Exists); }
        if replace && !exists { return Err(XattrError::NotFound); }
        let old = g.get(name).map(|v| xattr_space(name, v.len())).unwrap_or(0);
        let new = xattr_space(name, value.len());
        if let Some(a) = self.account.lock().clone() {
            if new > old { a.reserve(new - old).map_err(XattrError::Fs)?; }
            g.insert(name.to_string(), value);
            if old > new { a.release(old - new); }
        } else {
            g.insert(name.to_string(), value);
        }
        Ok(())
    }

    /// Remove an attribute and release its retained storage footprint. # C: O(log N)
    pub fn remove(&self, name: &str) -> Result<(), XattrError> {
        if !self.declared.load(Ordering::Acquire) { return Err(XattrError::NotSup); }
        let mut g = self.store.map.lock();
        let old = g.get(name).map(|v| xattr_space(name, v.len()));
        if old.is_none() { return Err(XattrError::NotFound); }
        g.remove(name);
        if let Some(a) = self.account.lock().clone() { a.release(old.unwrap()); }
        Ok(())
    }
}

/// `simple_xattr_space`: fixed header plus name and value bytes. # C: O(1)
pub fn xattr_space(name: &str, value_len: usize) -> u64 { 40u64 + name.len() as u64 + value_len as u64 }

impl Drop for XattrSlot {
    fn drop(&mut self) {
        let Some(a) = self.account.lock().take() else { return; };
        let bytes = self.store.map.lock().iter()
            .map(|(name, value)| xattr_space(name, value.len()))
            .sum();
        if bytes != 0 { a.release(bytes); }
    }
}

impl Default for XattrSlot {
    fn default() -> Self { Self::absent() }
}

impl SimpleXattrs {
    /// An empty store. # C: O(1)
    pub fn new() -> Self { Self::empty() }

    /// `const` empty store, so an [`XattrSlot`] can be built without an
    /// allocation and without a runtime initialiser. # C: O(1)
    pub const fn empty() -> Self { Self { map: Spinlock::new(BTreeMap::new()) } }

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

    /// Full name/value snapshot for filesystem writeback. # C: O(N)
    pub fn entries(&self) -> Vec<(String, Vec<u8>)> {
        self.map.lock().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Replace the in-core cache after the owning filesystem committed the new
    /// xattr set. # C: O(N log N)
    pub fn replace_all(&self, entries: &[(String, Vec<u8>)]) {
        let mut g = self.map.lock();
        g.clear();
        for (k, v) in entries { g.insert(k.clone(), v.clone()); }
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
