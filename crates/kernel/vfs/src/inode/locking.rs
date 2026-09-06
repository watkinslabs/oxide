use super::model::Inode;
use super::rwsem::{InodeRwsem, InodeRwsemReadGuard, InodeRwsemWriteGuard};

/// Exclusive `i_rwsem` ownership for one inode mutation. The wrapper keeps
/// the generic rwsem guard's semantics while allowing the profiler to measure
/// only the Linux `inode_lock()` owner, separate from `file->f_pos_lock`.
pub struct InodeWriteGuard<'a> {
    inner: InodeRwsemWriteGuard<'a>,
    #[cfg(feature = "debug-resolve-cost")]
    _hold_cost: crate::resolve_cost::Span,
}

impl core::ops::Deref for InodeWriteGuard<'_> {
    type Target = ();
    fn deref(&self) -> &Self::Target { &self.inner }
}

impl core::ops::DerefMut for InodeWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl Inode {
    /// `inode_lock`. # C: O(contention)
    pub fn inode_lock(&self) -> InodeWriteGuard<'_> {
        #[cfg(feature = "debug-resolve-cost")]
        let _cost = crate::resolve_cost::writer_lock();
        let guard = self.i_rwsem.write();
        #[cfg(feature = "debug-resolve-cost")]
        drop(_cost);
        InodeWriteGuard {
            inner: guard,
            #[cfg(feature = "debug-resolve-cost")]
            _hold_cost: crate::resolve_cost::inode_writer_hold(),
        }
    }
    /// `inode_lock_shared`. # C: O(contention)
    pub fn inode_lock_shared(&self) -> InodeRwsemReadGuard<'_> { self.i_rwsem.read() }
    /// Raw `i_rwsem` handle, for the `lock_rename` ordering helper. # C: O(1)
    fn i_rwsem(&self) -> &InodeRwsem { &self.i_rwsem }
}

/// Explicit-release spelling for `i_rwsem` guards. # C: O(1)
pub fn inode_unlock<G>(guard: G) { drop(guard); }

/// Held `i_rwsem` exclusive locks for a (possibly cross-directory) rename.
pub struct RenameLockGuard<'a> {
    _first:  InodeRwsemWriteGuard<'a>,
    _second: Option<InodeRwsemWriteGuard<'a>>,
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
