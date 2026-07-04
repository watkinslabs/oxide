use sync::{Inode as InodeLockClass, RwLock, RwReadGuard, RwWriteGuard};

use super::model::Inode;

impl Inode {
    /// `inode_lock`. # C: O(contention)
    pub fn inode_lock(&self) -> RwWriteGuard<'_, (), InodeLockClass> { self.i_rwsem.write() }
    /// `inode_lock_shared`. # C: O(contention)
    pub fn inode_lock_shared(&self) -> RwReadGuard<'_, (), InodeLockClass> { self.i_rwsem.read() }
    /// Raw `i_rwsem` handle, for the `lock_rename` ordering helper. # C: O(1)
    fn i_rwsem(&self) -> &RwLock<(), InodeLockClass> { &self.i_rwsem }
}

/// Explicit-release spelling for `i_rwsem` guards. # C: O(1)
pub fn inode_unlock<G>(guard: G) { drop(guard); }

/// Held `i_rwsem` exclusive locks for a (possibly cross-directory) rename.
pub struct RenameLockGuard<'a> {
    _first:  RwWriteGuard<'a, (), InodeLockClass>,
    _second: Option<RwWriteGuard<'a, (), InodeLockClass>>,
}

/// Lock two parent directory inodes for rename in address order. # C: O(contention)
pub fn lock_rename<'a>(p1: &'a Inode, p2: &'a Inode) -> RenameLockGuard<'a> {
    if core::ptr::eq(p1, p2) {
        return RenameLockGuard { _first: p1.i_rwsem().write(), _second: None };
    }
    let (lo, hi) = if (p1 as *const Inode as usize) < (p2 as *const Inode as usize) { (p1, p2) } else { (p2, p1) };
    let first = lo.i_rwsem().write();
    let second = hi.i_rwsem().write();
    RenameLockGuard { _first: first, _second: Some(second) }
}

/// Explicit release for [`lock_rename`]. # C: O(1)
pub fn unlock_rename(lock: RenameLockGuard<'_>) { drop(lock); }
