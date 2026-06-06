#![no_std]
//! Software periodic-timer registry — the timer-wheel analog (Linux
//! kernel/time/timer.c). Subsystems register their OWN periodic work
//! (net tcp-retransmit, sched cfs-bandwidth/load-balance, neighbor GC,
//! …) via `register_periodic`; a single generic driver (a process-context
//! kthread, spawned by the kernel) calls `run_due` and fires the elapsed
//! ones. No subsystem work is hardcoded here — this crate only owns the
//! mechanism, the callers own the timers (docs/53 kernel=glue).
extern crate alloc;

use sync::{Spinlock, Timer as TimerLock};
use alloc::vec::Vec;

/// Periodic callback. Receives the current monotonic time (ns).
pub type TimerFn = fn(u64);

struct Entry { interval_ns: u64, last_ns: u64, f: TimerFn }

static TIMERS: Spinlock<Vec<Entry>, TimerLock> = Spinlock::new(Vec::new());

/// Register a periodic callback fired roughly every `interval_ns` from the
/// timer driver's process context (safe to take runqueue/subsystem locks).
/// Call once per timer at boot from the owning subsystem.
/// # C: O(1) amortized
pub fn register_periodic(interval_ns: u64, f: TimerFn) {
    TIMERS.lock().push(Entry { interval_ns, last_ns: 0, f });
}

/// Fire every registered timer whose interval has elapsed since its last
/// run. Called by the timer driver kthread. Callbacks run WITHOUT the
/// registry lock held, so a callback may itself arm timers.
/// # C: O(N registered) + callback cost
pub fn run_due(now_ns: u64) {
    let mut due: Vec<TimerFn> = Vec::new();
    {
        let mut g = TIMERS.lock();
        for e in g.iter_mut() {
            if now_ns.saturating_sub(e.last_ns) >= e.interval_ns {
                e.last_ns = now_ns;
                due.push(e.f);
            }
        }
    }
    for f in due { f(now_ns); }
}
