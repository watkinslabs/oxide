// Linux `inode->i_flctx`: inode-owned advisory-lock state. BSD `flock(2)`
// locks belong to an open file description, so their owner key is the stable
// `File` allocation identity while that description is alive.

extern crate alloc;

use alloc::vec::Vec;

use sync::{Inode as InodeLockClass, Spinlock};

/// BSD whole-file advisory-lock mode (`LOCK_SH` / `LOCK_EX`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockKind { Shared, Exclusive }

/// Non-sleeping flock admission result. The syscall layer supplies `LOCK_NB`
/// policy or arms its inode wait queue after `Blocked`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockTry {
    Acquired,
    /// Linux replacement is non-atomic: a blocked conversion has already
    /// released the caller's old flock. `released` tells the caller to wake
    /// contenders after dropping this context's state lock.
    Blocked { released: bool },
}

#[derive(Clone, Copy)]
struct FlockHolder { file_id: usize, kind: FlockKind }

struct FileLockState { flock: Vec<FlockHolder> }

/// Canonical per-inode BSD lock context (Linux `struct file_lock_context`).
/// POSIX/OFD migration requires process/FdTable lifecycle ownership and is not
/// folded into this context until that owner is complete.
pub struct FileLockContext { state: Spinlock<FileLockState, InodeLockClass> }

impl FileLockContext {
    /// Construct empty inode lock state. # C: O(1)
    pub fn new() -> Self {
        Self { state: Spinlock::new(FileLockState { flock: Vec::new() }) }
    }

    /// Attempt BSD flock acquisition/conversion without sleeping. Linux
    /// removes a caller's existing flock before conflict detection, so a
    /// failed conversion is non-atomic and leaves no old flock behind.
    /// # C: O(N_holders)
    pub fn try_flock(&self, file_id: usize, want: FlockKind) -> FlockTry {
        let mut st = self.state.lock();
        Self::try_flock_locked(&mut st, file_id, want)
    }

    /// Attempt a flock and, if it conflicts, publish the running task on this
    /// inode's wait queue while the lock-state gate is still held. The caller
    /// drops the gate before scheduling, so unlock cannot lose a wakeup.
    /// # C: O(N_holders)
    pub fn flock_or_park(&self, file_id: usize, want: FlockKind) -> FlockTry {
        let mut st = self.state.lock();
        let result = Self::try_flock_locked(&mut st, file_id, want);
        if matches!(result, FlockTry::Blocked { .. }) { crate::file_lock_park(self.wait_key()); }
        result
    }

    fn try_flock_locked(st: &mut FileLockState, file_id: usize, want: FlockKind) -> FlockTry {
        let before = st.flock.len();
        st.flock.retain(|h| h.file_id != file_id);
        let released = st.flock.len() != before;
        let other = !st.flock.is_empty();
        let exclusive = st.flock.iter().any(|h| h.kind == FlockKind::Exclusive);
        let blocked = match want {
            FlockKind::Exclusive => other,
            FlockKind::Shared => exclusive,
        };
        if blocked { return FlockTry::Blocked { released }; }
        st.flock.push(FlockHolder { file_id, kind: want });
        FlockTry::Acquired
    }

    /// Stable scheduler wait key for this inode-owned context. # C: O(1)
    pub fn wait_key(&self) -> usize { self as *const Self as usize }

    /// Remove this open-description's BSD flock. `true` means a holder was
    /// removed and waiters may be woken after the context lock is released.
    /// # C: O(N_holders)
    pub fn unlock_flock(&self, file_id: usize) -> bool {
        let mut st = self.state.lock();
        let before = st.flock.len();
        st.flock.retain(|h| h.file_id != file_id);
        st.flock.len() != before
    }

    /// Canonical `locks_remove_file` final-close primitive. BSD flock state is
    /// owned here; record locks remain with their process-aware owner until the
    /// FdTable lifecycle can migrate them without semantic loss. # C: O(N_holders)
    pub fn release_file(&self, file_id: usize) -> bool { self.unlock_flock(file_id) }

    /// Return this file description's BSD flock mode for diagnostics/tests.
    /// # C: O(N_holders)
    pub fn flock_kind(&self, file_id: usize) -> Option<FlockKind> {
        self.state.lock().flock.iter().find(|h| h.file_id == file_id).map(|h| h.kind)
    }
}

impl Default for FileLockContext {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::{FileLockContext, FlockKind, FlockTry};

    const FIRST_FILE: usize = 1;
    const SECOND_FILE: usize = 2;

    #[test]
    fn blocked_upgrade_releases_the_callers_old_flock() {
        let ctx = FileLockContext::new();
        assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Shared), FlockTry::Acquired);
        assert_eq!(ctx.try_flock(SECOND_FILE, FlockKind::Shared), FlockTry::Acquired);
        assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Exclusive), FlockTry::Blocked { released: true });
        assert_eq!(ctx.flock_kind(FIRST_FILE), None);
        assert!(ctx.unlock_flock(SECOND_FILE));
        assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Exclusive), FlockTry::Acquired);
    }

    #[test]
    fn final_close_removes_only_its_bsd_flock() {
        let ctx = FileLockContext::new();
        assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Shared), FlockTry::Acquired);
        assert_eq!(ctx.try_flock(SECOND_FILE, FlockKind::Shared), FlockTry::Acquired);
        assert!(ctx.release_file(FIRST_FILE));
        assert_eq!(ctx.flock_kind(FIRST_FILE), None);
        assert_eq!(ctx.flock_kind(SECOND_FILE), Some(FlockKind::Shared));
    }
}
