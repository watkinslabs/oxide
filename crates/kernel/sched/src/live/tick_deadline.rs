// F169/B20: fallback walker for blocking-wait deadlines and alarm/itimer.
// POSIX timers use the architecture one-shot path in `timers::runtime`.
//
// Wake is `wake_if_sleeping`: flips Sleeping → Runnable, lifts
// vruntime, enqueues. The roused task re-checks its clock / pending
// signals after schedule() returns and surfaces -EAGAIN (SO_*TIMEO)
// or -EINTR (SIGALRM) from the caller's blocking loop.
//
// Cost: O(N_live_tasks) per fallback scan.

use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "debug-boot")]
use core::sync::atomic::AtomicU32;
use super::sigpend::Signum;

/// Last `now_ns` the scan walked the registry. Throttles the O(N)
/// allocation-free registry walk to a ~100 ms
/// cadence so calling this from every timer tick stays cheap.
static LAST_SCAN_NS: AtomicU64 = AtomicU64::new(0);
const SCAN_PERIOD_NS: u64 = 100_000_000;

/// Bounded counterpart to `MUTTERWAIT`: confirms that the deadline scanner
/// observed the exact compositor task before it delegates Linux-style wakeup
/// placement to `ttwu_deferred`.
#[cfg(feature = "debug-boot")]
static MUTTER_DEADLINE_WAKE_TRACE_REMAINING: AtomicU32 = AtomicU32::new(64);

fn fire_cpu_itimer(t: &crate::Task, deadline: &AtomicU64, interval: &AtomicU64, now_cpu: u64, sig: Signum) -> bool {
    let dl = deadline.load(Ordering::Acquire);
    if dl == 0 || dl > now_cpu { return false; }
    let intv = interval.load(Ordering::Acquire);
    deadline.store(if intv != 0 { now_cpu.saturating_add(intv) } else { 0 }, Ordering::Release);
    t.sigpending.fetch_or(sig.bit(), Ordering::Release);
    true
}

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
        // alarm(2)/ITIMER_REAL expiry: post SIGALRM, re-arm, wake.
        let adl = t.alarm_ns.load(Ordering::Acquire);
        if adl != 0 && adl <= now_ns {
            let interval = t.alarm_interval_ns.load(Ordering::Acquire);
            t.alarm_ns.store(
                if interval != 0 { now_ns.saturating_add(interval) } else { 0 },
                Ordering::Release,
            );
            t.sigpending.fetch_or(super::sigpend::Signum::Sigalrm.bit(), Ordering::Release);
            // Timer-ISR (IF=0): defer placement to the target's wake_list so the
            // tick never blocks on a contended rq lock and never enqueues a task
            // still on_cpu elsewhere. SAFETY: timer-ISR wake site; lookup keeps t alive.
            unsafe { super::ttwu::ttwu_deferred(alloc::sync::Arc::clone(&t)); }
        }
        let u = t.utime_ns.load(Ordering::Acquire);
        let s = t.stime_ns.load(Ordering::Acquire);
        let cpu_fired =
            fire_cpu_itimer(&t, &t.itimer_virtual_ns, &t.itimer_virtual_interval_ns, u, Signum::Sigvtalrm)
            | fire_cpu_itimer(&t, &t.itimer_prof_ns, &t.itimer_prof_interval_ns, u.saturating_add(s), Signum::Sigprof);
        if cpu_fired {
            // SAFETY: timer-ISR wake site; registry lookup keeps `t` alive across the call.
            unsafe { super::ttwu::ttwu_deferred(alloc::sync::Arc::clone(&t)); }
        }
        let dl = t.wakeup_deadline_ns.load(Ordering::Acquire);
        if dl == 0 || dl > now_ns { continue; }
        #[cfg(feature = "debug-boot")]
        if t.with_exe_path(|p| p.map(|p| {
            p.contains("gnome-shell") || p.contains("mutter")
        }).unwrap_or(false))
            && MUTTER_DEADLINE_WAKE_TRACE_REMAINING.fetch_update(
                Ordering::Relaxed, Ordering::Relaxed,
                |remaining| remaining.checked_sub(1)).is_ok()
        {
            klog::write_raw(b"[MUTTERWAIT wake tid=");
            klog::write_dec_u64(t.tid as u64);
            klog::write_raw(b" dl=");
            klog::write_dec_u64(dl);
            klog::write_raw(b" now=");
            klog::write_dec_u64(now_ns);
            klog::write_raw(b"]\n");
        }
        // SAFETY: timer-ISR wake site; registry lookup keeps `t` alive across the call.
        // ttwu clears the deadline only after winning Sleeping -> Runnable;
        // a losing scan must leave it armed for the next tick.
        unsafe { super::ttwu::ttwu_deferred(alloc::sync::Arc::clone(&t)); }
    }
}
