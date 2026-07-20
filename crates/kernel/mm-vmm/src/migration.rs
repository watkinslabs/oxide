//! VM migration-token registry.
//!
//! A non-present migration PTE is neither a swap PTE nor an error.  It names
//! a short-lived transaction here.  The registry keeps that name live until
//! every marker has been replaced or removed; callers register a waiter while
//! the state lock is held, drop all VM locks, then schedule and restart their
//! operation when completion wakes them.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use hal::pt_walker::MigrationEntry;
use sync::{Migration as MigrationClass, Spinlock};

#[derive(Copy, Clone)]
struct State {
    source_pa: u64,
    pending: bool,
    markers: usize,
}

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static TOKENS: Spinlock<BTreeMap<u64, State>, MigrationClass> = Spinlock::new(BTreeMap::new());

/// Start one migration transaction.  The returned token has no PTE users
/// until the pageout transaction successfully installs a marker.
pub fn migration_begin(source_pa: u64) -> Option<MigrationEntry> {
    loop {
        let raw = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        let entry = MigrationEntry::new(raw)?;
        let mut tokens = TOKENS.lock();
        if tokens.contains_key(&raw) { continue; }
        tokens.insert(raw, State { source_pa, pending: true, markers: 0 });
        return Some(entry);
    }
}

/// Account a PTE that has transitioned to `entry`.  Failing means the
/// transaction completed or was invalidated before the PTE mutation and the
/// caller must roll that mutation back rather than publish an orphan marker.
pub fn migration_attach_marker(entry: MigrationEntry) -> bool {
    let mut tokens = TOKENS.lock();
    let Some(state) = tokens.get_mut(&entry.token()) else { return false; };
    if !state.pending { return false; }
    state.markers += 1;
    true
}

/// Account a marker that was replaced by a present/swap PTE or removed by
/// unmap/teardown.  A completed transaction disappears only after its final
/// marker is gone, so a stale fault can never observe a recycled token.
pub fn migration_drop_marker_mapping(entry: MigrationEntry) -> Option<u64> {
    let mut tokens = TOKENS.lock();
    let Some(state) = tokens.get_mut(&entry.token()) else { return None; };
    if state.markers == 0 { return None; }
    state.markers -= 1;
    let source_pa = state.source_pa;
    if !state.pending && state.markers == 0 { tokens.remove(&entry.token()); }
    Some(source_pa)
}

/// Remove marker participation after rolling the exact PTE back to the
/// original resident frame.  Unlike `migration_drop_marker_mapping`, this
/// deliberately retains the source PTE reference.
pub fn migration_restore_marker_mapping(entry: MigrationEntry) -> bool {
    let mut tokens = TOKENS.lock();
    let Some(state) = tokens.get_mut(&entry.token()) else { return false; };
    if state.markers == 0 { return false; }
    state.markers -= 1;
    if !state.pending && state.markers == 0 { tokens.remove(&entry.token()); }
    true
}

/// Publish either commit or rollback after all marker PTEs have been
/// replaced.  The caller performs the scheduler wake after this returns.
pub fn migration_finish(entry: MigrationEntry) -> bool {
    let mut tokens = TOKENS.lock();
    let Some(state) = tokens.get_mut(&entry.token()) else { return false; };
    state.pending = false;
    if state.markers == 0 { tokens.remove(&entry.token()); }
    true
}

/// Check pending state and, if still pending, run `register` while the token
/// lock is held.  `register` must only enqueue the current task; it must not
/// block or acquire VM locks.  This closes the completion/park missed-wakeup
/// race.  The caller drops its own locks and schedules only when this returns
/// `true`, then restarts the fault/fork operation.
pub fn migration_pending_then<F: FnOnce()>(entry: MigrationEntry, register: F) -> bool {
    let tokens = TOKENS.lock();
    if !tokens.get(&entry.token()).is_some_and(|state| state.pending) { return false; }
    register();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn marker_lifetime_survives_pending_then_retires_after_finish() {
        let token = migration_begin(0x8000).unwrap();
        assert!(migration_attach_marker(token));
        let registered = AtomicBool::new(false);
        assert!(migration_pending_then(token, || registered.store(true, Ordering::Release)));
        assert!(registered.load(Ordering::Acquire));
        assert_eq!(migration_drop_marker_mapping(token), Some(0x8000));
        assert!(migration_finish(token));
        assert!(!migration_pending_then(token, || {}));
    }

    #[test]
    fn every_terminal_marker_action_has_one_source_pte_reference() {
        let token = migration_begin(0xa000).unwrap();
        assert!(migration_attach_marker(token));
        assert!(migration_attach_marker(token));
        assert!(migration_attach_marker(token));
        // One VMA disappears while pageout is pending; its original PTE ref
        // transfers to teardown exactly once.
        assert_eq!(migration_drop_marker_mapping(token), Some(0xa000));
        // A failed store rolls one frozen PTE back: token participation drops
        // but its resident PTE reference remains live.
        assert!(migration_restore_marker_mapping(token));
        // The remaining marker commits to swap and transfers its PTE ref.
        assert_eq!(migration_drop_marker_mapping(token), Some(0xa000));
        assert!(migration_finish(token));
        assert!(!migration_pending_then(token, || {}));
    }
}
