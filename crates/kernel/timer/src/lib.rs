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
pub type OneShotFn = fn(usize);

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
struct OneShot { id: TimerId, deadline_ns: u64, arg: usize, f: OneShotFn }

static TIMERS: Spinlock<Vec<Entry>, TimerLock> = Spinlock::new(Vec::new());
static ONESHOTS: Spinlock<Vec<OneShot>, TimerLock> = Spinlock::new(Vec::new());
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

/// Register a one-shot callback fired from the timer driver's process context
/// when `now_ns >= deadline_ns`.
/// # C: O(1) amortized
pub fn register_oneshot(deadline_ns: u64, arg: usize, f: OneShotFn) -> TimerId {
    let id = next_id();
    ONESHOTS.lock().push(OneShot { id, deadline_ns, arg, f });
    id
}

/// Unregister a one-shot timer previously returned by `register_oneshot`.
/// Returns true if the timer was still registered.
/// # C: O(N registered)
pub fn unregister_oneshot(id: TimerId) -> bool {
    let mut g = ONESHOTS.lock();
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
    let mut one: Vec<(OneShotFn, usize)> = Vec::new();
    {
        let mut g = TIMERS.lock();
        for e in g.iter_mut() {
            if now_ns.saturating_sub(e.last_ns) >= e.interval_ns {
                e.last_ns = now_ns;
                due.push(e.f);
            }
        }
    }
    {
        let mut g = ONESHOTS.lock();
        let mut i = 0;
        while i < g.len() {
            if now_ns >= g[i].deadline_ns {
                let e = g.remove(i);
                one.push((e.f, e.arg));
            } else {
                i += 1;
            }
        }
    }
    for f in due { f(now_ns); }
    for (f, arg) in one { f(arg); }
}

fn next_id() -> TimerId {
    let raw = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    TimerId(if raw == 0 { NEXT_ID.fetch_add(1, Ordering::Relaxed) } else { raw })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    static A: AtomicU64 = AtomicU64::new(0);
    static B: AtomicU64 = AtomicU64::new(0);

    fn reset() {
        TIMERS.lock().clear();
        ONESHOTS.lock().clear();
        NEXT_ID.store(1, Ordering::Relaxed);
        A.store(0, Ordering::Relaxed);
        B.store(0, Ordering::Relaxed);
    }

    fn tick_a(now_ns: u64) { A.fetch_add(now_ns, Ordering::Relaxed); }
    fn tick_b(now_ns: u64) { B.fetch_add(now_ns, Ordering::Relaxed); }

    #[test]
    fn register_returns_owned_nonzero_ids() {
        reset();

        let a = register_periodic(10, tick_a);
        let b = register_periodic(10, tick_b);

        assert_ne!(a.raw(), 0);
        assert_ne!(b.raw(), 0);
        assert_ne!(a, b);
        assert_eq!(TimerId::from_raw(a.raw()), Some(a));
        assert_eq!(TimerId::from_raw(0), None);
    }

    #[test]
    fn unregister_removes_only_matching_timer() {
        reset();

        let a = register_periodic(10, tick_a);
        let b = register_periodic(10, tick_b);

        assert!(unregister_periodic(a));
        assert!(!unregister_periodic(a));
        run_due(10);

        assert_eq!(A.load(Ordering::Relaxed), 0);
        assert_eq!(B.load(Ordering::Relaxed), 10);
        assert!(unregister_periodic(b));
    }

    #[test]
    fn unregister_stops_future_due_runs() {
        reset();

        let a = register_periodic(10, tick_a);
        run_due(10);
        assert_eq!(A.load(Ordering::Relaxed), 10);

        assert!(unregister_periodic(a));
        run_due(20);

        assert_eq!(A.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn oneshot_fires_once_and_unregisters() {
        reset();

        let a = register_oneshot(10, 3, |v| { A.fetch_add(v as u64, Ordering::Relaxed); });
        let b = register_oneshot(20, 7, |v| { B.fetch_add(v as u64, Ordering::Relaxed); });
        assert!(unregister_oneshot(b));
        assert!(!unregister_oneshot(b));
        run_due(9);
        assert_eq!(A.load(Ordering::Relaxed), 0);
        run_due(10);
        run_due(30);

        assert_eq!(A.load(Ordering::Relaxed), 3);
        assert_eq!(B.load(Ordering::Relaxed), 0);
        assert!(!unregister_oneshot(a));
    }
}
