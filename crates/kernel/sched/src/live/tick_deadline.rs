// F169: timer-wake scanner. Periodic walker over the live task
// registry that wakes any task whose `wakeup_deadline_ns` has
// passed. Caller invokes `tick_wake_expired(now_ns)` at ~tick
// cadence (rx kthread, every ~100 ms) — same cadence as
// `NetStack::tcp_retx_tick`, no additional thread needed.
//
// Wake is identical to `wake_if_sleeping`: flips Sleeping →
// Runnable, lifts vruntime, enqueues. The waking task discovers
// the deadline expired by re-checking its own clock after
// schedule() returns and surfaces -EAGAIN (per SO_RCVTIMEO /
// SO_SNDTIMEO POSIX semantic) from the caller's blocking loop.
//
// Cost: O(N_live_tasks) per tick. Acceptable until SMP /
// many-thread loads make a min-heap of deadlines worthwhile.

use core::sync::atomic::Ordering;

/// Walk the live task registry; wake any Sleeping task whose
/// `wakeup_deadline_ns` is non-zero AND `<= now_ns`. Idempotent.
/// # C: O(N_live_tasks)
pub fn tick_wake_expired(now_ns: u64) {
    if now_ns == 0 { return; }
    let tids = crate::registry::live_tids();
    for tid in tids {
        let t = match crate::registry::lookup(tid) { Some(t) => t, None => continue };
        let dl = t.wakeup_deadline_ns.load(Ordering::Acquire);
        if dl == 0 || dl > now_ns { continue; }
        // Match wake_if_sleeping semantics: clear deadline before
        // we flip state, so a racing explicit waker observing
        // Runnable doesn't double-fire.
        t.wakeup_deadline_ns.store(0, Ordering::Release);
        super::sigpend::wake_if_sleeping(&t);
    }
}
