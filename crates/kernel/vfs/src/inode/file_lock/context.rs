// Linux `inode->i_flctx` (`struct file_lock_context`): the inode-owned
// advisory-lock state. `flc_flock` holds BSD `flock(2)` locks, whose owner is
// the open file description; `flc_posix` holds `fcntl(2)` byte-range records,
// whose owner is the descriptor table (POSIX) or the description (OFD). Both
// lists live under ONE lock, as Linux's `flc_lock` does, and share ONE wait
// key so any release wakes every kind of parked contender.

extern crate alloc;

use alloc::vec::Vec;

use sync::{Inode as InodeLockClass, Spinlock};

use super::records::{self, RecordLock, RecordOwner, RecordTry};

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

struct FileLockState { flock: Vec<FlockHolder>, posix: Vec<RecordLock> }

/// Canonical per-inode advisory-lock context (Linux `struct
/// file_lock_context`).
pub struct FileLockContext { state: Spinlock<FileLockState, InodeLockClass> }

impl FileLockContext {
    /// Construct empty inode lock state. # C: O(1)
    pub fn new() -> Self {
        Self { state: Spinlock::new(FileLockState { flock: Vec::new(), posix: Vec::new() }) }
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

    /// Return this file description's BSD flock mode for diagnostics/tests.
    /// # C: O(N_holders)
    pub fn flock_kind(&self, file_id: usize) -> Option<FlockKind> {
        self.state.lock().flock.iter().find(|h| h.file_id == file_id).map(|h| h.kind)
    }

    /// Linux `posix_lock_inode` with `conflock == NULL`: apply `req` if no
    /// foreign lock overlaps, else report the blocker WITHOUT sleeping.
    /// `F_UNLCK` never blocks. # C: O(N_records^2)
    pub fn try_record_lock(&self, req: &RecordLock) -> RecordTry {
        let mut st = self.state.lock();
        Self::try_record_locked(&mut st, req)
    }

    /// Apply `req` and, on conflict, publish the running task on this inode's
    /// wait queue while the state gate is still held — the same lost-wakeup
    /// close as [`Self::flock_or_park`], for `F_SETLKW`. # C: O(N_records^2)
    pub fn record_lock_or_park(&self, req: &RecordLock) -> RecordTry {
        let mut st = self.state.lock();
        let result = Self::try_record_locked(&mut st, req);
        if matches!(result, RecordTry::Blocked { .. }) { crate::file_lock_park(self.wait_key()); }
        result
    }

    fn try_record_locked(st: &mut FileLockState, req: &RecordLock) -> RecordTry {
        if let Some(blocker) = records::find_conflict(&st.posix, req) {
            return RecordTry::Blocked { blocker: blocker.owner };
        }
        RecordTry::Acquired { released: records::apply(&mut st.posix, req) }
    }

    /// Linux `F_GETLK` (`fs/locks.c` `posix_test_lock`): describe the lock
    /// that would block `req`, or `None` when `req` would succeed.
    /// # C: O(N_records)
    pub fn probe_record_lock(&self, req: &RecordLock) -> Option<RecordLock> {
        records::find_conflict(&self.state.lock().posix, req)
    }

    /// Linux `locks_remove_posix` (`fs/locks.c:2768`): drop every byte-range
    /// record `owner` holds on this inode. `true` means waiters must be woken
    /// once the state lock is dropped. # C: O(N_records)
    pub fn remove_records_for(&self, owner: RecordOwner) -> bool {
        records::remove_owner(&mut self.state.lock().posix, owner)
    }

    /// Type of the record covering `off` for `owner`, for diagnostics/tests.
    /// # C: O(N_records)
    pub fn record_lock_kind(&self, owner: RecordOwner, off: u64) -> Option<i16> {
        self.state.lock().posix.iter()
            .find(|e| e.owner == owner && e.start <= off && off < e.end)
            .map(|e| e.l_type)
    }

    /// Live record count for this inode, for tests asserting the split/merge
    /// pass does not leak entries. # C: O(1)
    pub fn record_lock_count(&self) -> usize { self.state.lock().posix.len() }

    /// Linux `locks_remove_file` (`fs/locks.c:2849`) for a final `fput`:
    /// releases the description's BSD flock AND its OFD byte-range records.
    /// `true` means waiters must be woken. # C: O(N_holders + N_records)
    pub fn release_file(&self, file_id: usize) -> bool {
        let mut st = self.state.lock();
        let before = st.flock.len();
        st.flock.retain(|h| h.file_id != file_id);
        let flock_gone = st.flock.len() != before;
        let records_gone = records::remove_owner(&mut st.posix, RecordOwner::Ofd(file_id));
        flock_gone || records_gone
    }
}

impl Default for FileLockContext {
    fn default() -> Self { Self::new() }
}
