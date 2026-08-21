//! Event-driven background reclaim. `kswapd` is woken by the allocator below
//! low watermark and reclaims through the canonical LRU/pageout transaction
//! until the current PMM zone reaches high watermark or no owner can release.

use core::sync::atomic::{AtomicBool, Ordering};

use sched::live::{WaitList, wait_event_worker};
use sync::{Reclaim, Spinlock};

use crate::watermark::watermark_snapshot;

struct Request { pending: bool }

static REQUEST: Spinlock<Request, Reclaim> = Spinlock::new(Request { pending: false });
static WAIT: WaitList = WaitList::new();
static DIRECT_RECLAIM: AtomicBool = AtomicBool::new(false);
const HIBERNATE_AGING_PASSES: usize = 3;

/// Run one direct reclaim transaction without recursive entry from pageout's
/// own zram/swap allocations. Answers whether the transaction freed a page —
/// the allocation slowpath reads it to decide whether retrying is still worth
/// anything. A recursive entry answers `false`: the outer transaction owns the
/// progress, and this caller must not treat its own recursion as progress.
/// # C: O(one LRU transaction)
pub(crate) fn direct_reclaim_once() -> bool {
    if DIRECT_RECLAIM.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return false; }
    let progress = crate::user_as::pageout::reclaim_one_anon_page();
    DIRECT_RECLAIM.store(false, Ordering::Release);
    progress
}

/// Reclaim up to `target` physical pages before hibernation snapshots buddy
/// truth. Anonymous pageout and registered shrinkers remain their canonical
/// owners; this function only drives them and measures the resulting buddy
/// free-page delta. # C: O(target * reclaim transaction)
/// # Ctx: blockable hibernation setup; users and freezable kernel threads frozen
pub fn reclaim_for_hibernate(target: usize) -> usize {
    if target == 0 { return 0; }
    let Some(pmm) = crate::setup::pmm_static() else { return 0; };
    let before = pmm.free_pages();
    let mut stalled = 0usize;
    loop {
        let freed = pmm.free_pages().saturating_sub(before) as usize;
        if freed >= target { return target; }
        if direct_reclaim_once() { stalled = 0; continue; }
        let remaining = target - freed;
        let aged = crate::setup::age_anon_for_hibernate(remaining);
        let _ = crate::shrinker::shrinker_scan(remaining);
        let now = pmm.free_pages().saturating_sub(before) as usize;
        if now > freed { stalled = 0; continue; }
        if aged.scanned == 0 && crate::shrinker::shrinker_count() == 0 { return freed; }
        stalled += 1;
        if stalled >= HIBERNATE_AGING_PASSES { return freed; }
    }
}

/// Pages current PMM reclaim owners report as theoretically reclaimable for
/// hibernation's best-effort image-size lower bound. # C: O(shrinkers)
pub fn hibernate_reclaimable_pages() -> usize {
    let state = crate::setup::reclaim_snapshot().unwrap_or_default();
    crate::shrinker::hibernate_reclaimable_pages(
        state, crate::shrinker::independent_shrinker_count())
}

/// Publish background work before waking the waiter. `REQUEST` serializes the
/// check-to-park handoff: a waker cannot pass this state update until the
/// kthread has enrolled on `WAIT`, so there is no deadline/poll fallback.
/// # C: O(1); # Lk: Reclaim then TaskList
pub(crate) fn wake_kswapd() {
    { REQUEST.lock().pending = true; }
    WAIT.wake_one();
}

fn take_request() -> bool {
    let mut request = REQUEST.lock();
    if request.pending {
        request.pending = false;
        return true;
    }
    false
}

fn reclaim_to_high() {
    loop {
        let Some(pmm) = crate::setup::pmm_static() else { return; };
        let snapshot = pmm.snapshot();
        let Some(watermark) = watermark_snapshot(snapshot.free_pages) else { return; };
        if watermark.free_pages >= watermark.zone.high { return; }
        // LRU pageout remains the primary memory reclaim owner. Shrinkers are
        // consulted only when no anon page can be reclaimed in this pass.
        if crate::user_as::pageout::reclaim_one_anon_page() { continue; }
        let needed = watermark.zone.high.saturating_sub(watermark.free_pages) as usize;
        if crate::shrinker::shrinker_scan(needed) == 0 { return; }
    }
}

extern "C" fn kswapd(_arg: usize) -> ! {
    loop {
        // SAFETY: event-worker context with no subsystem lock held; the shared
        // loop publishes before rechecking `REQUEST`, so a wake cannot be lost.
        let _ = unsafe { wait_event_worker(&WAIT, take_request) };
        reclaim_to_high();
    }
}

/// Spawn the kernel's single-zone kswapd after the runqueue exists. Future
/// NUMA zones instantiate one state/worker per zone; the current PMM has one
/// canonical normal zone, so one worker is the only truthful topology.
/// # C: O(1)
pub fn spawn_kswapd() -> Result<(), sched::live::SpawnError> {
    let tid = sched::live::next_tid();
    // SAFETY: kernel_main invokes this after scheduler runqueue installation;
    // the entry is static and needs no argument-owned memory.
    unsafe { sched::live::spawn_kernel_thread(tid, "kswapd0", kswapd, 0) }.map(|_| ())
}
