//! System-wide page-cache state: the two-list LRU (`17§4.4`), the flusher's
//! dirty-inode list and the global dirty count (`17§4.3`), and the dirty
//! thresholds those are measured against.
//!
//! These are global rather than per-`PageCache` on purpose. Memory pressure
//! and the dirty limit are properties of the machine, not of one filesystem's
//! cache object, so a second mount must not get a second budget — that is the
//! split source of truth the reference avoids by keeping one LRU per node and
//! one dirty count per machine.
//!
//! List entries hold a WEAK reference to the mapping. A mapping that goes away
//! (its filesystem unmounted, its `PageCache` dropped) leaves entries that the
//! next scan discards; nothing keeps a dead mapping alive to be scanned.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use sync::{PageCacheLru, Spinlock};

use super::mapping::Mapping;

/// Reference default `dirty_background_ratio`: percent of RAM of dirty data at
/// which the flusher is woken (`17§4.3` step 5's threshold).
pub const DIRTY_BACKGROUND_RATIO: u64 = 10;
/// Reference default `vm_dirty_ratio`: percent of RAM at which a writer is
/// made to do writeback itself rather than dirty more.
pub const DIRTY_RATIO: u64 = 20;
/// Reference default `dirty_writeback_interval`, nanoseconds: how often the
/// flusher wakes on its own.
pub const WRITEBACK_INTERVAL_NS: u64 = 5_000_000_000;
/// Reference default `dirty_expire_interval`, nanoseconds: how long a dirty
/// page may sit before the flusher writes it back regardless of the threshold.
pub const DIRTY_EXPIRE_NS: u64 = 30_000_000_000;
/// Pages one flusher visit writes back from a single inode before moving on,
/// so one large file cannot starve the rest of the dirty list.
pub const WRITEBACK_BATCH: usize = 64;

struct Entry { map: Weak<Mapping>, index: u64 }

struct Lists {
    /// Twice-referenced pages. Reclaim only reaches these after the inactive
    /// half is exhausted.
    active:   VecDeque<Entry>,
    /// Once-referenced pages — the reclaim frontier.
    inactive: VecDeque<Entry>,
    /// Mappings holding dirty pages, oldest first (the reference's `b_dirty`).
    dirty:    VecDeque<Weak<Mapping>>,
}

static LISTS: Spinlock<Lists, PageCacheLru> = Spinlock::new(Lists {
    active: VecDeque::new(), inactive: VecDeque::new(), dirty: VecDeque::new(),
});

/// Monotonic nanosecond source, installed by whoever owns the clock. Zero
/// means no clock, which makes every dirty page un-expired — the threshold
/// still drives writeback, so a machine with no clock installed loses nothing
/// but the age-based sweep.
static CLOCK: AtomicU64 = AtomicU64::new(0);

/// Install the monotonic clock the flusher ages dirty mappings against.
/// # C: O(1)
pub fn install_clock(clock: fn() -> u64) { CLOCK.store(clock as usize as u64, Ordering::Release); }

/// Current time on the installed clock, or 0 if none. # C: O(1)
pub fn now_ns() -> u64 {
    let raw = CLOCK.load(Ordering::Acquire);
    if raw == 0 { return 0; }
    // SAFETY: only `install_clock` stores this atomic, and it stores exactly a
    // `fn() -> u64` pointer taken from a live function item in this process.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, fn() -> u64>(raw as usize) };
    f()
}

static NR_CACHE:     AtomicUsize = AtomicUsize::new(0);
static NR_DIRTY:     AtomicUsize = AtomicUsize::new(0);
static NR_WRITEBACK: AtomicUsize = AtomicUsize::new(0);
static TOTALRAM:     AtomicU64   = AtomicU64::new(0);

/// Publish the machine's managed page count, which the dirty thresholds are a
/// percentage OF. Until it is installed there is no threshold to exceed and
/// the flusher runs only on expiry. # C: O(1)
pub fn install_totalram_pages(pages: u64) { TOTALRAM.store(pages, Ordering::Release); }

/// # C: O(1)
pub fn totalram_pages() -> u64 { TOTALRAM.load(Ordering::Acquire) }

/// Resident cached pages, machine-wide. # C: O(1)
pub fn nr_cached() -> usize { NR_CACHE.load(Ordering::Acquire) }

/// Dirty cached pages, machine-wide (`17§4.3` step 3). # C: O(1)
pub fn nr_dirty() -> usize { NR_DIRTY.load(Ordering::Acquire) }

/// Pages handed to a writeback target and not yet completed. # C: O(1)
pub fn nr_writeback() -> usize { NR_WRITEBACK.load(Ordering::Acquire) }

pub(super) fn account_cached(delta: isize) { step(&NR_CACHE, delta); }
pub(super) fn account_dirty(delta: isize) { step(&NR_DIRTY, delta); }
pub(super) fn account_writeback(delta: isize) { step(&NR_WRITEBACK, delta); }

fn step(counter: &AtomicUsize, delta: isize) {
    if delta >= 0 { counter.fetch_add(delta as usize, Ordering::AcqRel); }
    else {
        let mag = delta.unsigned_abs();
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(mag)));
    }
}

/// Dirty pages at which the flusher is woken. Zero when the machine's page
/// count has not been installed. # C: O(1)
pub fn background_threshold() -> usize {
    (totalram_pages().saturating_mul(DIRTY_BACKGROUND_RATIO) / 100) as usize
}

/// Dirty-plus-in-flight pages at which a writer must write back itself.
/// # C: O(1)
pub fn dirty_limit() -> usize {
    (totalram_pages().saturating_mul(DIRTY_RATIO) / 100) as usize
}

/// What a writer that just dirtied a page has to do about it — the reference's
/// `balance_dirty_pages` decision, as a pure function of the counts so it can
/// be checked without a machine.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DirtyAction {
    /// Below the background threshold: return to the writer (`17§4.3` step 4).
    Proceed,
    /// Above the background threshold: wake the flusher and return.
    Wake,
    /// Above the dirty limit: the writer does writeback before it continues.
    Throttle,
}

/// # C: O(1)
pub fn dirty_action(nr_dirty: usize, nr_writeback: usize, totalram: u64) -> DirtyAction {
    if totalram == 0 { return DirtyAction::Proceed; }
    let outstanding = nr_dirty.saturating_add(nr_writeback);
    let limit = (totalram.saturating_mul(DIRTY_RATIO) / 100) as usize;
    let background = (totalram.saturating_mul(DIRTY_BACKGROUND_RATIO) / 100) as usize;
    if outstanding > limit { return DirtyAction::Throttle; }
    if outstanding > background { return DirtyAction::Wake; }
    DirtyAction::Proceed
}

/// Whether a mapping dirtied at `dirtied_when` has been dirty long enough that
/// the flusher writes it back without waiting for the threshold. # C: O(1)
pub fn dirty_expired(dirtied_when: u64, now: u64) -> bool {
    dirtied_when != 0 && now.saturating_sub(dirtied_when) >= DIRTY_EXPIRE_NS
}

/// Put a newly resident page on the inactive list — where the reference puts
/// a first-time-read page, so one pass over a large file cannot evict a
/// working set that has been referenced twice. # C: O(1) amortised
pub(super) fn add_lru(map: &Arc<Mapping>, index: u64) {
    account_cached(1);
    let mut g = LISTS.lock();
    g.inactive.push_front(Entry { map: Arc::downgrade(map), index });
    let entries = g.active.len() + g.inactive.len();
    if entries > NR_CACHE.load(Ordering::Acquire).saturating_mul(2).saturating_add(64) { prune(&mut g); }
}

/// Drop list entries whose page is gone. Entries are not removed at eviction
/// time — finding one costs a walk of the list — so the list is compacted here
/// once it has grown well past the number of pages that exist.
fn prune(g: &mut Lists) {
    let live = |e: &Entry| e.map.upgrade().is_some_and(|m| m.get(e.index).is_some());
    g.active.retain(&live);
    g.inactive.retain(&live);
    g.dirty.retain(|w| w.upgrade().is_some());
}

/// Record a reference to `page`, promoting it on its second one.
///
/// First reference sets `PG_REFERENCED` and leaves the page inactive; a
/// reference to an already-referenced inactive page moves it to the active
/// list and clears the bit. That two-step is what makes the LRU an LRU-2: a
/// single touch never promotes. # C: O(1)
pub(super) fn mark_accessed(page: &super::page::CachedPage) {
    use crate::types::PageFlags;
    if !page.flags().contains(PageFlags::REFERENCED) { page.set_flags(PageFlags::REFERENCED); return; }
    if page.is_active() { return; }
    page.set_flags(PageFlags::ACTIVE);
    page.clear_flags(PageFlags::REFERENCED);
}

/// Queue a mapping that has just gone dirty, once. # C: O(1)
pub(super) fn queue_dirty_inode(map: &Arc<Mapping>) {
    if map.queued.swap(true, Ordering::AcqRel) { return; }
    LISTS.lock().dirty.push_back(Arc::downgrade(map));
}

/// The dirty mappings, oldest first. Snapshotted so the flusher writes back
/// with no list lock held. Mappings that no longer hold dirty pages drop off.
/// # C: O(dirty inodes)
pub(super) fn dirty_inodes() -> Vec<Arc<Mapping>> {
    let mut g = LISTS.lock();
    let mut out = Vec::with_capacity(g.dirty.len());
    let mut keep = VecDeque::with_capacity(g.dirty.len());
    while let Some(weak) = g.dirty.pop_front() {
        let Some(map) = weak.upgrade() else { continue; };
        if map.nr_dirty() == 0 && map.inflight.load(Ordering::Acquire) == 0 {
            map.queued.store(false, Ordering::Release);
            continue;
        }
        out.push(Arc::clone(&map));
        keep.push_back(weak);
    }
    g.dirty = keep;
    out
}

/// Pop up to `budget` inactive-list candidates, oldest first, lazily moving
/// pages that were promoted since they were queued onto the active list.
/// Returns `(mapping, index)` pairs for the caller to act on with the list
/// lock released. # C: O(budget)
pub(super) fn inactive_candidates(budget: usize) -> Vec<(Arc<Mapping>, u64)> {
    let mut out = Vec::with_capacity(budget);
    let mut g = LISTS.lock();
    refill_inactive(&mut g);
    // Entries are held aside rather than pushed straight back: an entry
    // returned to the list within this pass would be popped again and handed
    // out twice, which turns one reclaim round into several against the same
    // page — enough to evict a page whose reference bit this very pass cleared.
    let mut visited: VecDeque<Entry> = VecDeque::new();
    let mut scanned = 0usize;
    while out.len() < budget && scanned < budget.saturating_mul(4) {
        let Some(entry) = g.inactive.pop_back() else { break; };
        scanned += 1;
        let Some(map) = entry.map.upgrade() else { continue; };
        let Some(page) = map.get(entry.index) else { continue; };
        if page.is_active() { g.active.push_front(entry); continue; }
        out.push((map, entry.index));
        visited.push_back(entry);
    }
    for entry in visited { g.inactive.push_front(entry); }
    out
}

/// Move active-list tail entries back to the inactive list when the inactive
/// half has run short, so reclaim always has a frontier to scan. The reference
/// keeps the two halves in the same ballpark for the same reason.
fn refill_inactive(g: &mut Lists) {
    if g.inactive.len() >= g.active.len() { return; }
    let want = (g.active.len() - g.inactive.len()) / 2 + 1;
    for _ in 0..want {
        let Some(entry) = g.active.pop_back() else { break; };
        if let Some(page) = entry.map.upgrade().and_then(|m| m.get(entry.index)) {
            page.clear_flags(crate::types::PageFlags::ACTIVE);
        }
        g.inactive.push_front(entry);
    }
}

/// Test-only reset of every global list and counter, so one test's pages
/// cannot be scanned by another's reclaim pass. # C: O(entries)
#[cfg(test)]
pub(super) fn reset_for_test() {
    let mut g = LISTS.lock();
    g.active.clear(); g.inactive.clear(); g.dirty.clear();
    drop(g);
    NR_CACHE.store(0, Ordering::Release);
    NR_DIRTY.store(0, Ordering::Release);
    NR_WRITEBACK.store(0, Ordering::Release);
    TOTALRAM.store(0, Ordering::Release);
    CLOCK.store(0, Ordering::Release);
}
