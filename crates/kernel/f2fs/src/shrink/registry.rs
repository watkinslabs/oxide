//! The list of mounts reclaim walks, and the two callbacks it calls.
//!
//! The budget arithmetic is `budget` next door; nothing here decides a number.
//!
//! **Every mount is visited under `try_lock`, never `lock`.** Reclaim can be
//! entered from inside an allocation, and a mount allocates while holding its
//! volume lock — so blocking here would let a mount wait for a lock it is
//! itself holding. A mount whose lock is busy is SKIPPED, which is what the
//! reference does with the same hazard, and costs only that this pass frees
//! that mount's entries on its next round.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList};

use crate::extent::Kind;
use crate::mount::F2fs;

use super::budget::{reclaimable, remaining, split};

/// Mounts that have joined, weakly so the list never keeps one alive.
static MOUNTS: Spinlock<Vec<Weak<F2fs>>, TaskList> = Spinlock::new(Vec::new());

/// Whether the one filesystem-wide shrinker has been handed to reclaim.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Hand reclaim this filesystem's two callbacks, once for the whole build.
///
/// Called from `join` rather than from a module initialiser: a build that never
/// mounts an F2FS volume has no caches to offer, and registering ahead of the
/// first mount puts a callback into every reclaim pass on such a machine.
/// # C: O(N shrinkers) on the first call, O(1) after
pub fn install() {
    if INSTALLED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    let shrinker = pmm::shrinker::Shrinker { count_objects: count, scan_objects: scan };
    if pmm::shrinker::register_shrinker(shrinker).is_err() {
        INSTALLED.store(false, Ordering::Release);
    }
}

/// Publish a mount's caches to reclaim.
///
/// Idempotent by identity, so a caller that joins twice does not get visited
/// twice and charged a double budget.
/// # C: O(N mounts)
pub fn join(fs: &Arc<F2fs>) {
    {
        let mut mounts = MOUNTS.lock();
        if mounts.iter().any(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(fs))) { return; }
        if mounts.try_reserve(1).is_err() { return; }
        mounts.push(Arc::downgrade(fs));
    }
    install();
}

/// Take a mount out of the list, emptying both extent caches on the way.
///
/// The caches are emptied HERE rather than left for the drop of the volume,
/// because leaving is the last moment the entries can be accounted for as
/// reclaimed: after it the memory goes back as part of a filesystem
/// disappearing, and a machine watching reclaim would see a mount's caches
/// vanish without any pass having freed them.
///
/// Takes `&mut F2fs` because the only correct caller is the drop of the mount
/// itself, where no one else can hold the volume lock.
/// # C: O(entries in both caches)
pub fn leave(fs: &mut F2fs) {
    {
        let mut v = fs.volume.lock();
        let mut caches = v.extents_mut();
        for kind in [Kind::Read, Kind::BlockAge] {
            let held = caches.zombie_count(kind).saturating_add(caches.node_count(kind));
            caches.shrink(kind, held.min(usize::MAX as u64) as usize);
        }
    }
    let me = fs as *const F2fs;
    let mut mounts = MOUNTS.lock();
    mounts.retain(|w| !core::ptr::eq(w.as_ptr(), me));
}

/// Every mount still in the list, with the dead entries dropped.
///
/// The list is copied and the lock released before any mount is touched, so no
/// mount's volume lock is ever taken while the registry lock is held — the two
/// would otherwise be an ordering rule reclaim has no way to honour.
/// # C: O(N mounts)
fn live() -> Vec<Arc<F2fs>> {
    let mut mounts = MOUNTS.lock();
    mounts.retain(|w| w.strong_count() > 0);
    mounts.iter().filter_map(Weak::upgrade).collect()
}

/// Entries this filesystem could give back right now, across every mount.
/// # C: O(N mounts)
pub fn count() -> usize {
    let mut total = 0usize;
    for fs in live() {
        let Some(v) = fs.volume.try_lock() else { continue };
        let caches = v.extents();
        let entries = |kind: Kind| {
            caches.zombie_count(kind).saturating_add(caches.node_count(kind))
        };
        let one = reclaimable(entries(Kind::Read), entries(Kind::BlockAge),
                              v.free_nids.free_count());
        total = total.saturating_add(one);
    }
    total
}

/// Give back up to `nr` entries, and report how many actually went.
///
/// The budget is carried ACROSS mounts and the walk stops once it is met, so a
/// machine asking for a hundred entries does not get a hundred from every
/// mount. Which cache is asked in which order, and for how much, is
/// `budget::split` — the ordering matters and belongs somewhere testable.
/// # C: O(N mounts + entries freed)
pub fn scan(nr: usize) -> usize {
    let mut freed = 0usize;
    for fs in live() {
        if freed >= nr { break; }
        let Some(mut v) = fs.volume.try_lock() else { continue };
        let share = split(remaining(nr, freed));
        {
            let mut caches = v.extents_mut();
            freed = freed.saturating_add(caches.shrink(Kind::BlockAge, share.age));
            freed = freed.saturating_add(caches.shrink(Kind::Read, share.read));
        }
        let left = remaining(nr, freed);
        if left > 0 { freed = freed.saturating_add(v.free_nids.shrink(left)); }
    }
    freed
}

/// Whether ONE mount is published, by identity.
///
/// Identity rather than a list length, because the list is one static shared by
/// every test in the binary and tests run concurrently: a length that moved by
/// one is a claim about every other test's mounts as well as this one's, and it
/// fails whenever a sibling test happens to mount at the same moment.
/// # C: O(N mounts)
#[cfg(test)]
pub(crate) fn listed(fs: &Arc<F2fs>) -> bool {
    MOUNTS.lock().iter().any(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(fs)))
}

/// How many times a mount appears, so a double join is visible as a duplicate
/// rather than only as a changed total. # C: O(N mounts)
#[cfg(test)]
pub(crate) fn listings(fs: &Arc<F2fs>) -> usize {
    MOUNTS.lock().iter().filter(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(fs))).count()
}

/// Whether an entry for a mount that has ALREADY been dropped is still held.
///
/// Takes a raw pointer because the point of the question is that the `Arc` is
/// gone: a test asking it cannot hold one.
/// # C: O(N mounts)
#[cfg(test)]
pub(crate) fn holds_ptr(me: *const F2fs) -> bool {
    MOUNTS.lock().iter().any(|w| core::ptr::eq(w.as_ptr(), me))
}

#[cfg(test)]
#[path = "../tests/shrink/registry.rs"]
mod tests;
