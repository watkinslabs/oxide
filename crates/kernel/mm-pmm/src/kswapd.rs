//! Event-driven background reclaim. `kswapd` is woken by the allocator below
//! low watermark and reclaims through the canonical LRU/pageout transaction
//! until the current PMM zone reaches high watermark or no owner can release.

use core::sync::atomic::{AtomicBool, Ordering};

use sched::live::WaitList;
use sync::{Reclaim, Spinlock};

use crate::watermark::watermark_snapshot;

struct Request { pending: bool }

static REQUEST: Spinlock<Request, Reclaim> = Spinlock::new(Request { pending: false });
static WAIT: WaitList = WaitList::new();
static DIRECT_RECLAIM: AtomicBool = AtomicBool::new(false);

/// Run one direct reclaim transaction without recursive entry from pageout's
/// own zram/swap allocations. # C: O(one LRU transaction)
pub(crate) fn direct_reclaim_once() {
    if DIRECT_RECLAIM.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    let _ = crate::user_as::pageout::reclaim_one_anon_page();
    DIRECT_RECLAIM.store(false, Ordering::Release);
}

/// Publish background work before waking the waiter. `REQUEST` serializes the
/// check-to-park handoff: a waker cannot pass this state update until the
/// kthread has enrolled on `WAIT`, so there is no deadline/poll fallback.
/// # C: O(1); # Lk: Reclaim then TaskList
pub(crate) fn wake_kswapd() {
    { REQUEST.lock().pending = true; }
    WAIT.wake_one();
}

fn take_request_or_park() -> bool {
    let mut request = REQUEST.lock();
    if request.pending {
        request.pending = false;
        return true;
    }
    // SAFETY: kswapd runs in schedulable process context and holds only the
    // Reclaim request lock, which is strictly below WaitList's TaskList rank.
    unsafe { WAIT.park(); }
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
        if take_request_or_park() { reclaim_to_high(); }
        // SAFETY: after a request pass, or after publication to WAIT, this is
        // a runnable kthread with no subsystem lock held.
        unsafe { sched::live::schedule(); }
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
