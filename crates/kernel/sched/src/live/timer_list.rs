// `timer_list` in softirq — Linux `TIMER_SOFTIRQ` (`skizm.md` §2, Step 8b).
//
// ADDITIVE, deliberately. The core already has `timer::register_periodic`,
// which runs its callbacks on the `ktimers` kthread in PROCESS context, and
// that must stay: some of those callbacks sleep (mount expiry), and a softirq
// may not. Moving ktimers wholesale into softirq — the obvious reading of
// "`timer_list` runs in softirq" — would be wrong for exactly those callbacks.
//
// Linux draws the same line: `timer_list` callbacks run in TIMER_SOFTIRQ and
// may not sleep; anything that needs to sleep goes to a workqueue. This is the
// non-sleeping half, for callers that want expiry latency measured in ticks
// rather than the 100 ms ktimers cadence.
//
//   timer_list (here)  softirq, must NOT sleep, fires at the tick that passes it
//   delayed_work       process context via a kworker, MAY sleep
//   register_periodic  process context on ktimers, MAY sleep, 100 ms cadence
//
// Bounded array behind an irqsave lock: `add`/`modify` are callable from a hard
// IRQ, so they can neither allocate nor spin on a lock process context holds.

use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, Workqueue as TimerClass};

/// Timer callback. Runs in SOFTIRQ context and MUST NOT SLEEP.
pub type TimerFn = fn(usize);

/// Concurrently-armed timers.
pub const TIMER_CAPACITY: usize = 32;

#[derive(Copy, Clone)]
struct Entry {
    expires_ns: u64,
    func: TimerFn,
    arg: usize,
    /// Re-arm interval; 0 = one-shot (Linux `timer_list` is one-shot, and a
    /// periodic caller re-arms from inside its own callback — this saves every
    /// such caller writing the same three lines).
    interval_ns: u64,
}

struct Table {
    slots: [Option<Entry>; TIMER_CAPACITY],
    dropped: u64,
}

impl Table {
    const fn new() -> Self { Self { slots: [None; TIMER_CAPACITY], dropped: 0 } }
}

static TABLE: Spinlock<Table, TimerClass> = Spinlock::new(Table::new());
/// Earliest armed expiry, so the tick's fast path is a single compare.
static EARLIEST_NS: AtomicU64 = AtomicU64::new(u64::MAX);

/// Monotonic clock for the drain. Same source the tick uses.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
#[cfg(not(target_os = "oxide-kernel"))]
pub fn now_ns() -> u64 { 0 }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type TmIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type TmIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type TmIrq = sync::NoopIrq;

/// Arm a timer (Linux `add_timer`). `interval_ns == 0` is one-shot. Returns a
/// handle, or `None` when the table is full.
/// # C: O(TIMER_CAPACITY)
/// # Ctx: any, including hard IRQ
pub fn add(func: TimerFn, arg: usize, expires_ns: u64, interval_ns: u64) -> Option<usize> {
    let mut g = TABLE.lock_irqsave::<TmIrq>();
    let Some(idx) = g.slots.iter().position(|s| s.is_none()) else {
        g.dropped += 1;
        return None;
    };
    g.slots[idx] = Some(Entry { expires_ns, func, arg, interval_ns });
    drop(g);
    EARLIEST_NS.fetch_min(expires_ns, Ordering::AcqRel);
    Some(idx)
}

/// Re-arm an existing timer (Linux `mod_timer`).
/// # C: O(1)
/// # Ctx: any, including hard IRQ
pub fn modify(handle: usize, expires_ns: u64) -> bool {
    if handle >= TIMER_CAPACITY { return false; }
    let mut g = TABLE.lock_irqsave::<TmIrq>();
    let Some(entry) = g.slots[handle].as_mut() else { return false };
    entry.expires_ns = expires_ns;
    drop(g);
    EARLIEST_NS.fetch_min(expires_ns, Ordering::AcqRel);
    true
}

/// Disarm (Linux `del_timer`). A timer already running its callback is not
/// interrupted; this only prevents future expiries.
/// # C: O(1)
/// # Ctx: any, including hard IRQ
pub fn del(handle: usize) -> bool {
    if handle >= TIMER_CAPACITY { return false; }
    let mut g = TABLE.lock_irqsave::<TmIrq>();
    let existed = g.slots[handle].is_some();
    g.slots[handle] = None;
    existed
}

/// Armed timer count.
/// # C: O(TIMER_CAPACITY)
pub fn armed() -> usize {
    TABLE.lock_irqsave::<TmIrq>().slots.iter().filter(|s| s.is_some()).count()
}

/// Arms refused because the table was full.
/// # C: O(1)
pub fn dropped() -> u64 { TABLE.lock_irqsave::<TmIrq>().dropped }

/// Run every expired timer (Linux `run_timer_softirq`). Called from softirq
/// context; the single `EARLIEST_NS` compare is the whole cost when nothing is
/// due.
///
/// Callbacks run with the table lock RELEASED, so a callback may arm, modify or
/// delete timers — including its own.
/// # SAFETY: softirq context. Callbacks must not sleep.
/// # C: O(1) typical; O(TIMER_CAPACITY + work) when something expires
pub unsafe fn run_expired(now_ns: u64) -> usize {
    if EARLIEST_NS.load(Ordering::Acquire) > now_ns { return 0; }
    let mut due: [Option<(TimerFn, usize)>; TIMER_CAPACITY] = [None; TIMER_CAPACITY];
    let mut n = 0;
    let mut next = u64::MAX;
    {
        let mut g = TABLE.lock_irqsave::<TmIrq>();
        for idx in 0..TIMER_CAPACITY {
            let Some(entry) = g.slots[idx] else { continue };
            if entry.expires_ns <= now_ns {
                due[n] = Some((entry.func, entry.arg));
                n += 1;
                if entry.interval_ns != 0 {
                    // Periodic: re-arm from the DEADLINE, not from `now`, so a
                    // late tick does not make the period drift.
                    let re = entry.expires_ns.saturating_add(entry.interval_ns);
                    g.slots[idx] = Some(Entry { expires_ns: re, ..entry });
                    if re < next { next = re; }
                } else {
                    g.slots[idx] = None;
                }
            } else if entry.expires_ns < next {
                next = entry.expires_ns;
            }
        }
    }
    EARLIEST_NS.store(next, Ordering::Release);
    for cb in due.iter().flatten() { (cb.0)(cb.1); }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;


    /// These modules own a single GLOBAL table, and cargo runs tests in
    /// parallel threads, so two tests sharing it produce order-dependent
    /// results — which showed up as an abort, not a clean assertion failure.
    /// Serialising is the honest fix; per-test slot partitioning is not
    /// possible when `add` picks the first free slot.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static HITS: AtomicUsize = AtomicUsize::new(0);
    fn body(_arg: usize) { HITS.fetch_add(1, Ordering::AcqRel); }

    fn reset() -> std::sync::MutexGuard<'static, ()> {
        let serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut g = TABLE.lock_irqsave::<TmIrq>();
        for s in g.slots.iter_mut() { *s = None; }
        g.dropped = 0;
        drop(g);
        EARLIEST_NS.store(u64::MAX, Ordering::Release);
        HITS.store(0, Ordering::Release);
        serial
    }

    #[test]
    fn a_one_shot_fires_once_and_disarms() {
        let _g = reset();
        assert!(add(body, 0, 1_000, 0).is_some());
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(999) }, 0, "not yet due");
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(1_000) }, 1, "due at exactly the deadline");
        assert_eq!(armed(), 0, "a one-shot disarms itself");
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(9_999) }, 0, "must not fire twice");
        assert_eq!(HITS.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_periodic_rearms_from_its_deadline_not_from_now() {
        // Re-arming from `now` makes the period drift whenever a tick is late,
        // which is exactly the failure a periodic timer must not have.
        let _g = reset();
        assert!(add(body, 0, 1_000, 100).is_some());
        // Tick arrives LATE, at 1_450.
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(1_450) }, 1);
        // Next deadline must be 1_100 (1_000 + 100), not 1_550.
        assert_eq!(EARLIEST_NS.load(Ordering::Acquire), 1_100);
        assert_eq!(armed(), 1);
    }

    #[test]
    fn modify_and_del_work_and_del_prevents_the_callback() {
        let _g = reset();
        let h = add(body, 0, 5_000, 0).unwrap();
        assert!(modify(h, 1_000));
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(1_000) }, 1, "modify moved it earlier");
        let h2 = add(body, 0, 2_000, 0).unwrap();
        assert!(del(h2));
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(9_999) }, 0, "a deleted timer must not fire");
        assert_eq!(HITS.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_full_table_refuses_rather_than_dropping_silently() {
        let _g = reset();
        for _ in 0..TIMER_CAPACITY { assert!(add(body, 0, 1_000, 0).is_some()); }
        assert!(add(body, 0, 1_000, 0).is_none());
        assert_eq!(dropped(), 1);
    }

    #[test]
    fn a_callback_may_arm_another_timer() {
        // The table lock is released across callbacks, so this must not
        // self-deadlock.
        let _g = reset();
        fn arms_another(_a: usize) {
            HITS.fetch_add(1, Ordering::AcqRel);
            let _ = add(body, 0, 10_000, 0);
        }
        assert!(add(arms_another, 0, 1_000, 0).is_some());
        // SAFETY: host test.
        assert_eq!(unsafe { run_expired(1_000) }, 1);
        assert_eq!(armed(), 1, "the callback's timer is armed");
    }
}
