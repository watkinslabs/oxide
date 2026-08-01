// Crate-wide serialisation for the process-global singletons netlink tests
// mutate. Kernel-side these ARE global by design (one FIB, one uevent
// broadcast registry), so tests cannot own them; the alternative to a lock is
// inventing per-test registries in the kernel, which would be worse.
//
// One lock PER GLOBAL rather than one per file: a global written from several
// test files needs one owner, or the files race each other.
//
// The FIB's owner is NOT here. Namespace 0's route table belongs to
// `net::hosted_fixture::init_net_domain()`, which snapshots those rows on
// acquire and restores them on drop — so a private `FIB` mutex beside it was a
// second lock over the same table and excluded nothing: a netlink test holding
// `FIB` inserted ns-0 routes that a `net`-fixture holder then restored away
// underneath it. Every route test now takes the domain guard itself.
//
// Poison is recovered, not propagated: a genuine assertion failure must report
// as ONE failure instead of cascading into every sibling that shares the lock.

use std::sync::{Mutex, MutexGuard};

static UEVENT: Mutex<()> = Mutex::new(());
static GENL: Mutex<()> = Mutex::new(());
static QUOTA_EVENTS: Mutex<()> = Mutex::new(());

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
