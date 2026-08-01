// Crate-wide serialisation for the process-global singletons netlink tests
// mutate. Kernel-side these ARE global by design (one FIB, one uevent
// broadcast registry), so tests cannot own them; the alternative to a lock is
// inventing per-test registries in the kernel, which would be worse.
//
// One lock PER GLOBAL rather than one per file: the FIB is written from four
// separate test files (`rtnetlink_tests.rs`, `rtnetlink_tests/route_semantics.rs`,
// `rtnetlink_lookup.rs`, `netlink_socket.rs`), so a per-file lock leaves them
// racing each other — measured 2/40 after per-file locking, 0/N after this.
//
// Poison is recovered, not propagated: a genuine assertion failure must report
// as ONE failure instead of cascading into every sibling that shares the lock.

use std::sync::{Mutex, MutexGuard};

static FIB: Mutex<()> = Mutex::new(());
static UEVENT: Mutex<()> = Mutex::new(());
static GENL: Mutex<()> = Mutex::new(());
static QUOTA_EVENTS: Mutex<()> = Mutex::new(());

/// Serialise access to the global routing table (`rtnetlink::route_*`).
pub(crate) fn fib() -> MutexGuard<'static, ()> {
    FIB.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialise access to the global `UEVENT_LISTENERS` broadcast registry.
pub(crate) fn uevent() -> MutexGuard<'static, ()> {
    UEVENT.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialise genetlink family registration: registering announces on the
/// controller's notify group, so a concurrent registration would land in
/// another test's watcher queue.
pub(crate) fn genl() -> MutexGuard<'static, ()> {
    GENL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialise the `VFS_DQUOT` events group, which every quota test shares
/// because the family's group id is statically reserved.
pub(crate) fn quota_events() -> MutexGuard<'static, ()> {
    QUOTA_EVENTS.lock().unwrap_or_else(|e| e.into_inner())
}
