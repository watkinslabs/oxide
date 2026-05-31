// F169/B20: timer-wake scanner. Periodic walker over the live task
// registry that wakes any task whose `wakeup_deadline_ns` (SO_*TIMEO)
// or `alarm_ns` (alarm/ITIMER_REAL) has passed. Invoked from the live
// timer tick `tick_poll_combined` (kernel/src/lib.rs); self-throttles
// to ~100 ms via LAST_SCAN_NS. F152 retired the rx kthread that used
// to call this — until it was rewired here the scanner was dead.
//
// Wake is `wake_if_sleeping`: flips Sleeping → Runnable, lifts
// vruntime, enqueues. The roused task re-checks its clock / pending
// signals after schedule() returns and surfaces -EAGAIN (SO_*TIMEO)
// or -EINTR (SIGALRM) from the caller's blocking loop.
//
// Cost: O(N_live_tasks) per scan. Acceptable until SMP / many-thread
// loads make a min-heap of deadlines worthwhile.

use core::sync::atomic::{AtomicU64, Ordering};

/// Last `now_ns` the scan walked the registry. Throttles the O(N)
/// `live_tids()` walk (allocates + locks + retains) to a ~100 ms
/// cadence so calling this from every timer tick stays cheap —
/// reap_orphans already does one such walk per tick; this avoids a
/// second. Matches the original 100 ms kthread cadence; ≤100 ms wake
/// latency is within Linux ITIMER_REAL / SO_RCVTIMEO granularity.
static LAST_SCAN_NS: AtomicU64 = AtomicU64::new(0);
const SCAN_PERIOD_NS: u64 = 100_000_000;

/// Walk the live task registry; wake any Sleeping task whose
/// `wakeup_deadline_ns` is non-zero AND `<= now_ns`. Idempotent.
///
/// B20: also services expired `alarm_ns` (alarm(2) / setitimer
/// ITIMER_REAL) here. The syscall-return tail also checks alarm_ns,
/// but a task parked in a blocking syscall (e.g. read() on an empty
/// pipe) issues no further syscalls, so its tail never runs — only
/// this periodic walker can post SIGALRM and wake it. On expiry we
/// re-arm by interval (or clear for one-shot), set the SIGALRM
/// pending bit, and `wake_if_sleeping` so the blocking helper
/// re-checks deliverable signals and surfaces -EINTR.
/// # C: O(N_live_tasks)
pub fn tick_wake_expired(now_ns: u64) {
    if now_ns == 0 { return; }
    // Throttle to SCAN_PERIOD_NS. The load-then-store race under SMP
    // at worst double-scans one period — harmless (scan is idempotent).
    let last = LAST_SCAN_NS.load(Ordering::Relaxed);
    if now_ns.saturating_sub(last) < SCAN_PERIOD_NS { return; }
    LAST_SCAN_NS.store(now_ns, Ordering::Relaxed);
    let tids = crate::registry::live_tids();
    for tid in tids {
        let t = match crate::registry::lookup(tid) { Some(t) => t, None => continue };
        // alarm(2)/ITIMER_REAL expiry: post SIGALRM, re-arm, wake.
        let adl = t.alarm_ns.load(Ordering::Acquire);
        if adl != 0 && adl <= now_ns {
            let interval = t.alarm_interval_ns.load(Ordering::Acquire);
            t.alarm_ns.store(
                if interval != 0 { now_ns.saturating_add(interval) } else { 0 },
                Ordering::Release,
            );
            t.sigpending.fetch_or(super::sigpend::Signum::Sigalrm.bit(), Ordering::Release);
            super::sigpend::wake_if_sleeping(&t);
        }
        let dl = t.wakeup_deadline_ns.load(Ordering::Acquire);
        if dl == 0 || dl > now_ns { continue; }
        // Match wake_if_sleeping semantics: clear deadline before
        // we flip state, so a racing explicit waker observing
        // Runnable doesn't double-fire.
        t.wakeup_deadline_ns.store(0, Ordering::Release);
        super::sigpend::wake_if_sleeping(&t);
    }
}
