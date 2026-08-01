// Hosted tests share ONE notification subsystem. The pieces below are
// process-global by design and no test can own a private copy:
//
//   * `dispatch::INSTANCES` — every live group, as weak refs
//   * `types::{MARK_COUNT, PERM_MARK_COUNT, MNTNS_MARK_COUNT}`
//   * the `vfs::fsnotify` ucount table and its two watch/mark sysctls
//
// `INSTANCES` is what makes these tests race even though each one uses its own
// inodes and its own uid. Dispatch UPGRADES every weak ref in the list before
// it decides whether a group is interested, so ANY test firing an event holds a
// live `Arc` to EVERY other test's group for the duration of that walk — and
// `register_instance` does the same through its `retain`. A sibling's
// `drop(group)` therefore does not run `InotifyData::Drop` while that walk is
// in flight: the group's inode pins and its ucount charges are released later,
// on the other test's thread, AFTER the sibling asserted they were gone. That
// is the whole observed failure — `i_count()` reading 2 instead of 1, and
// `ucount(InotifyWatches)` reading 2 instead of 0.
//
// ONE claim for the whole subsystem, not one per test file: ten test files
// create groups into the same registry, so a per-file lock would leave those
// files racing each other while each believed it was serialized.
//
// Poison is recovered rather than propagated: one failing test must report as
// one failure, not cascade into every sibling.

use std::sync::{Mutex, MutexGuard};

static NOTIFY: Mutex<()> = Mutex::new(());

/// Live claim on the notification subsystem. Held for the body of a test.
pub(crate) struct NotifyClaim(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the notification claim. Groups from earlier tests are already gone —
/// each holds its claim until its own groups drop — so there is nothing to
/// reset beyond dropping the stale weak refs the registry keeps.
pub(crate) fn claim_notify() -> NotifyClaim {
    let g = NOTIFY.lock().unwrap_or_else(|e| e.into_inner());
    super::dispatch::instances().lock().retain(|w| w.upgrade().is_some());
    NotifyClaim(g)
}
