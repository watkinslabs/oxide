#![no_std]
//! Software periodic-timer registry — the timer-wheel analog (Linux
//! kernel/time/timer.c). Subsystems register their OWN periodic work
//! (net tcp-retransmit, sched cfs-bandwidth/load-balance, neighbor GC,
//! …) via `register_periodic`; a single generic driver (a process-context
//! kthread, spawned by the kernel) calls `run_due` and fires the elapsed
//! ones. No subsystem work is hardcoded here — this crate only owns the
//! mechanism, the callers own the timers (docs/53 kernel=glue).
extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, Timer as TimerLock};

/// Periodic callback. Receives the current monotonic time (ns).
pub type TimerFn = fn(u64);

/// Opaque id for a registered periodic timer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimerId(u64);

impl TimerId {
    /// Rebuild a timer id from a stored raw value. `0` is never a valid id.
    /// # C: O(1)
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Raw non-zero id suitable for atomic storage by the timer owner.
    /// # C: O(1)
    pub const fn raw(self) -> u64 { self.0 }
}

struct Entry { id: TimerId, interval_ns: u64, last_ns: u64, f: TimerFn }

static TIMERS: Spinlock<Vec<Entry>, TimerLock> = Spinlock::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Register a periodic callback fired roughly every `interval_ns` from the
/// timer driver's process context (safe to take runqueue/subsystem locks).
/// The returned id belongs to the caller and must be unregistered by drivers
/// whose lifetime is tied to a removable device.
/// # C: O(1) amortized
pub fn register_periodic(interval_ns: u64, f: TimerFn) -> TimerId {
    let raw = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let id = TimerId(if raw == 0 { NEXT_ID.fetch_add(1, Ordering::Relaxed) } else { raw });
    TIMERS.lock().push(Entry { id, interval_ns, last_ns: 0, f });
    id
}

/// Unregister a periodic timer previously returned by `register_periodic`.
/// Returns true if the timer was still registered.
/// # C: O(N registered)
pub fn unregister_periodic(id: TimerId) -> bool {
    let mut g = TIMERS.lock();
    let before = g.len();
    g.retain(|entry| entry.id != id);
    g.len() != before
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
