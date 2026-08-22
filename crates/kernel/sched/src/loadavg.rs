//! Linux load average — EWMA of runnable plus uninterruptible tasks over 1/5/15 min,
//! resampled every ~5s (Linux `CALC_LOAD`). Fixed-point
//! FSHIFT=11. `/proc/loadavg` reads `snapshot()`.
//! The 5s cadence is gated on the monotonic clock, so it needs no knowledge of
//! the timer-tick rate.

use core::sync::atomic::{AtomicU64, Ordering};

/// Scheduler fixed-point shift for the load averages. The `sysinfo(2)` ABI
/// carries them at `SI_LOAD_SHIFT` instead and rescales at the syscall
/// boundary.
pub const FSHIFT: u32 = 11;
const FIXED_1: u64 = 1 << FSHIFT;     // 1.0 in fixed point
const EXP_1:  u64 = 1884;             // 1/exp(5s/1min)  fixed point
const EXP_5:  u64 = 2014;             // 1/exp(5s/5min)
const EXP_15: u64 = 2037;             // 1/exp(5s/15min)
const SAMPLE_NS: u64 = 5_000_000_000; // LOAD_FREQ ≈ 5s

static AVENRUN: [AtomicU64; 3] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static LAST_NS: AtomicU64 = AtomicU64::new(0);

/// `load = (load*exp + active*FIXED_1*(FIXED_1-exp)) >> FSHIFT` — the Linux
/// `CALC_LOAD` recurrence (active arrives un-scaled). # C: O(1)
fn calc_load(load: u64, exp: u64, active: u64) -> u64 {
    let n = active.saturating_mul(FIXED_1);
    load.saturating_mul(exp)
        .saturating_add(n.saturating_mul(FIXED_1 - exp))
        >> FSHIFT
}

#[inline]
fn fold_active(total: i64, running: u32, uninterruptible: i32) -> i64 {
    total + running as i64 + uninterruptible as i64
}

/// Called from the timer tick with the monotonic clock. Resamples at most
/// once per ~5s; the first call only seeds the clock.
/// # C: O(1) typical; O(N_tasks) on the 0.2 Hz resample.
pub fn tick(now_ns: u64) {
    let last = LAST_NS.load(Ordering::Relaxed);
    if now_ns.saturating_sub(last) < SAMPLE_NS { return; }
    if LAST_NS.compare_exchange(last, now_ns, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return; // another tick won the resample race
    }
    if last == 0 { return; } // seed only — no bogus first sample
    let active = active_count();
    let exps = [EXP_1, EXP_5, EXP_15];
    for i in 0..3 {
        let l = AVENRUN[i].load(Ordering::Relaxed);
        AVENRUN[i].store(calc_load(l, exps[i], active), Ordering::Relaxed);
    }
}

/// Active-task count, summed from each runqueue's runnable and
/// uninterruptible counters — never the task list.
///
/// This runs in the timer ISR. The previous implementation called
/// `registry::live_counts()`, which takes the `REG` spinlock, walks every
/// registered task, and upgrades/drops a `Weak` per entry — so it could take a
/// process-context lock from hard-IRQ context, and it ran `Arc`/`Weak` drop glue
/// (hence `kfree`, hence the allocator lock) inside the ISR. Both are `06§3.1`
/// violations; lockdep flagged the pair as `TaskList` and `KMalloc`
/// (`skizm.md` 3.0, 3.1 #2). At 0.2 Hz it was latent, not harmless.
///
/// The replacement touches only atomics already maintained by the scheduler, so
/// it takes no lock and allocates nothing.
///
/// `nr_running` counts QUEUED tasks and excludes the one currently running
/// (the picker pops it), whereas Linux's `rq->nr_running` includes it. So the
/// running task is added back when it is not the idle task — otherwise a CPU
/// that is genuinely busy with exactly one task would report zero load.
/// # C: O(MAX_CPUS) atomic loads, on the 0.2 Hz resample only
fn active_count() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    {
        let mut active = 0i64;
        for cpu in 0..cpu::MAX_CPUS as u32 {
            // SAFETY: `global_for` returns a shared &'static Runqueue for an
            // installed CPU; only lock-free atomic fields are read here, which
            // is legal from the timer ISR on any CPU.
            let Some(rq) = (unsafe { crate::live::runqueue::global_for(cpu) }) else { continue };
            // `rq->nr_running` already folds the running task in (and folds
            // nothing in when that task is the per-CPU idle task), exactly as
            // Linux's `calc_load_fold_active` reads it — so there is nothing
            // for this loop to add on top.
            active = fold_active(active, rq.nr_running.load(Ordering::Relaxed),
                                 rq.nr_uninterruptible.load(Ordering::Relaxed));
        }
        active.max(0) as u64
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// `(1min, 5min, 15min)` load averages in FSHIFT fixed-point. # C: O(1)
pub fn snapshot() -> [u64; 3] {
    [AVENRUN[0].load(Ordering::Relaxed),
     AVENRUN[1].load(Ordering::Relaxed),
     AVENRUN[2].load(Ordering::Relaxed)]
}

/// Split a fixed-point average into `(integer, 2-decimal fraction)` for the
/// `%lu.%02lu` `/proc/loadavg` form. # C: O(1)
pub fn fmt_parts(x: u64) -> (u64, u64) {
    (x >> FSHIFT, ((x & (FIXED_1 - 1)) * 100) >> FSHIFT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fmt_parts_splits_fixed_point() {
        assert_eq!(fmt_parts(FIXED_1), (1, 0));                 // 1.00
        assert_eq!(fmt_parts(FIXED_1 + FIXED_1 / 2), (1, 50));  // 1.50
        assert_eq!(fmt_parts(0), (0, 0));
    }
    #[test]
    fn calc_load_converges_toward_active() {
        // Constant load of 2 → EWMA rises from 0 toward 2.0.
        let mut l = 0u64;
        for _ in 0..200 { l = calc_load(l, EXP_1, 2); }
        let (i, _) = fmt_parts(l);
        assert!(i >= 1, "1m avg should approach 2 under sustained load, got int={i}");
    }

    #[test]
    fn active_fold_includes_cross_cpu_uninterruptible_sum() {
        let active = fold_active(fold_active(0, 2, 2), 3, -1);
        assert_eq!(active, 6, "blocked increments and migrated-wake decrements fold globally");
        assert!(calc_load(0, EXP_1, active as u64) > calc_load(0, EXP_1, 5));
    }

    #[test]
    fn uninterruptible_transition_contributes_until_wake() {
        use alloc::sync::Arc;
        use crate::{SchedClass, Task, TaskState, WaitState};
        use crate::live::runqueue::Runqueue;

        let idle = Arc::new(Task::new(1, "idle", SchedClass::Idle));
        let rq = Runqueue::new(0, idle);
        let task = Task::new(2, "blocked", SchedClass::Normal { weight: 1024 });
        task.set_sleep_state(WaitState::Uninterruptible);
        assert!(rq.account_blocked(&task));
        assert!(!rq.account_blocked(&task), "one block contributes exactly once");
        assert_eq!(rq.nr_uninterruptible.load(Ordering::Relaxed), 1);
        assert!(task.claim_wake());
        assert_eq!(task.state(), TaskState::Waking);
        assert!(rq.account_wake(&task));
        assert!(!rq.account_wake(&task), "one wake retires exactly one block");
        task.complete_wake();
        assert_eq!(rq.nr_uninterruptible.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn interruptible_and_frozen_sleeps_do_not_contribute() {
        use alloc::sync::Arc;
        use crate::{SchedClass, Task, WaitState};
        use crate::live::runqueue::Runqueue;

        let rq = Runqueue::new(0, Arc::new(Task::new(3, "idle", SchedClass::Idle)));
        let interruptible = Task::new(4, "signal", SchedClass::Normal { weight: 1024 });
        interruptible.set_sleep_state(WaitState::Interruptible);
        assert!(!rq.account_blocked(&interruptible));
        let frozen = Task::new(5, "frozen", SchedClass::Normal { weight: 1024 });
        frozen.set_sleep_state(WaitState::Uninterruptible);
        frozen.frozen.store(true, Ordering::Release);
        assert!(!rq.account_blocked(&frozen));
        let killable = Task::new(6, "fatal-only", SchedClass::Normal { weight: 1024 });
        killable.set_sleep_state(WaitState::Killable);
        assert!(rq.account_blocked(&killable), "killable includes uninterruptible");
        assert_eq!(rq.nr_uninterruptible.load(Ordering::Relaxed), 1);
        assert!(killable.claim_wake());
        assert!(rq.account_wake(&killable));
    }
}
