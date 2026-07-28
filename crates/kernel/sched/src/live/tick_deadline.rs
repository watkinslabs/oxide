// B20: coarse walker for alarm(2)/ITIMER_REAL and the CPU-time itimers.
// POSIX timers use the architecture one-shot path in `timers::runtime`.
//
// B1460 moved BLOCKING-WAIT deadlines out of here entirely. They used to be
// found by this same registry walk, which meant every kernel timeout inherited
// its ~100 ms cadence — the walk is a `timer::register_periodic` on the
// `ktimers` kthread, self-throttled to 100 ms, on a kthread that parks 100 ms
// per loop. Wait expiries now live in `sched::hrtimeout`, a deadline-ordered
// queue the timer IRQ sweeps and the one-shot programmer reads, so a 1 ms
// timeout costs 1 ms. Nothing here consumes `wakeup_deadline_ns` any more; a
// second consumer of the same deadline would be exactly the shadow state that
// lets a broken primary look healthy.
//
// What is left is genuinely coarse: `alarm(2)` has 1-second resolution, and
// ITIMER_VIRTUAL/ITIMER_PROF advance only on CPU time this walk also samples.
//
// Wake is `ttwu_deferred`: flips Sleeping → Runnable, lifts vruntime, enqueues.
// The roused task re-checks pending signals after schedule() returns and
// surfaces -EINTR (SIGALRM) from the caller's blocking loop.
//
// Cost: O(N_live_tasks) per scan, at the 100 ms ktimers cadence.

use core::sync::atomic::{AtomicU64, Ordering};
use super::sigpend::Signum;

/// Last `now_ns` the scan walked the registry. Throttles the O(N)
/// allocation-free registry walk to a ~100 ms
/// cadence so calling this from every timer tick stays cheap.
static LAST_SCAN_NS: AtomicU64 = AtomicU64::new(0);
const SCAN_PERIOD_NS: u64 = 100_000_000;

/// Service ONE task's expired `alarm(2)`/`ITIMER_REAL` deadline and its
/// CPU-time itimers, posting SIGALRM / SIGVTALRM / SIGPROF and re-arming by
/// interval (or clearing for a one-shot). Returns whether anything was posted,
/// so a caller that must also wake the task can.
///
/// ONE owner for the expiry policy: the registry walk below runs it for every
/// live task, and the return-to-user path runs it for the current task so a
/// timer that came due inside the last syscall is not held for up to a full
/// scan period. Before this the syscall tail carried its own open-coded copy.
/// # C: O(1)
pub fn service_task_timers(t: &crate::Task, now_ns: u64) -> bool {
    let mut fired = false;
    let adl = t.alarm_ns.load(Ordering::Acquire);
    if adl != 0 && adl <= now_ns {
        let interval = t.alarm_interval_ns.load(Ordering::Acquire);
        t.alarm_ns.store(
            if interval != 0 { now_ns.saturating_add(interval) } else { 0 },
            Ordering::Release,
        );
        t.sigpending.fetch_or(Signum::Sigalrm.bit(), Ordering::Release);
        fired = true;
    }
    let u = t.utime_ns.load(Ordering::Acquire);
    let s = t.stime_ns.load(Ordering::Acquire);
    fired
        | fire_cpu_itimer(t, &t.itimer_virtual_ns, &t.itimer_virtual_interval_ns, u, Signum::Sigvtalrm)
        | fire_cpu_itimer(t, &t.itimer_prof_ns, &t.itimer_prof_interval_ns, u.saturating_add(s), Signum::Sigprof)
}

fn fire_cpu_itimer(t: &crate::Task, deadline: &AtomicU64, interval: &AtomicU64, now_cpu: u64, sig: Signum) -> bool {
    let dl = deadline.load(Ordering::Acquire);
    if dl == 0 || dl > now_cpu { return false; }
    let intv = interval.load(Ordering::Acquire);
    deadline.store(if intv != 0 { now_cpu.saturating_add(intv) } else { 0 }, Ordering::Release);
    t.sigpending.fetch_or(sig.bit(), Ordering::Release);
    true
}

/// Walk the live task registry and service expired `alarm_ns` (alarm(2) /
/// setitimer ITIMER_REAL) plus the CPU-time itimers. Idempotent.
///
/// B20: the syscall-return tail also checks alarm_ns,
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
    // debug-wakelat: record the effective scan cadence; a gap far over the
    // 100 ms throttle means the driving tick stalled (H3).
    #[cfg(feature = "debug-wakelat")]
    super::wakelat::note_scan(now_ns);
    // This runs from the timer IRQ.  Do not materialize a Vec snapshot here:
    // global allocation in hard-IRQ context can re-enter allocator state while
    // an interrupted task owns it.  Advance one registry tid at a time, with
    // the registry lock released before `lookup`/wake work.
    let mut after = 0;
    while let Some(tid) = crate::registry::next_live_tid_after(after) {
        after = tid;
        let t = match crate::registry::lookup(tid) { Some(t) => t, None => continue };
        if service_task_timers(&t, now_ns) {
            // Timer-ISR (IF=0): defer placement to the target's wake_list so the
            // tick never blocks on a contended rq lock and never enqueues a task
            // still on_cpu elsewhere.
            // SAFETY: timer-ISR wake site; registry lookup keeps `t` alive across the call.
            unsafe { super::ttwu::ttwu_deferred(alloc::sync::Arc::clone(&t)); }
        }
    }
}
