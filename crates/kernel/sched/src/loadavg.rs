//! Linux load average — EWMA of the runnable task count over 1/5/15 min,
//! resampled every ~5s (Linux `kernel/sched/loadavg.c` CALC_LOAD). Fixed-point
//! FSHIFT=11. `/proc/loadavg` reads `snapshot()`.
//!
//! `active` is the runnable task count (Linux also counts TASK_UNINTERRUPTIBLE;
//! oxide reports runnable for now). The 5s cadence is gated on the monotonic
//! clock, so it needs no knowledge of the timer-tick rate.

use core::sync::atomic::{AtomicU64, Ordering};

/// Scheduler fixed-point shift for the load averages (Linux
/// `include/linux/sched/loadavg.h`). The `sysinfo(2)` ABI carries them at
/// `SI_LOAD_SHIFT` instead and rescales at the syscall boundary.
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

/// Runnable-task count, summed from the per-CPU runqueues (Linux
/// `calc_load_account_active`, which reads `rq->nr_running` — never the task
/// list).
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
        use crate::task::SchedClass;
        let mut active = 0u64;
        for cpu in 0..cpu::MAX_CPUS as u32 {
            // SAFETY: `global_for` returns a shared &'static Runqueue for an
            // installed CPU; only lock-free atomic fields are read here, which
            // is legal from the timer ISR on any CPU.
            let Some(rq) = (unsafe { crate::live::runqueue::global_for(cpu) }) else { continue };
            // SAFETY: `current_ref` reads the task installed in `rq.current`,
            // kept alive by the runqueue's owning Arc across this read; only
            // its sched class is inspected.
            let idle = matches!(unsafe { rq.current_ref() }.sched_class(), SchedClass::Idle);
            active += rq_active(rq.nr_running.load(Ordering::Relaxed), idle);
        }
        active
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// One CPU's contribution to the runnable count: its queued tasks plus the
/// running one, unless that is the idle task. Split out from `active_count` so
/// the accounting is host-testable without a runqueue.
/// # C: O(1)
// Only `active_count`'s kernel branch and the tests call this; a plain hosted
// build has no runqueue to fold and would flag it dead.
#[cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
fn rq_active(nr_running: u32, current_is_idle: bool) -> u64 {
    nr_running as u64 + if current_is_idle { 0 } else { 1 }
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
    fn rq_active_counts_the_running_task_but_not_idle() {
        // An idle CPU with an empty queue contributes nothing.
        assert_eq!(rq_active(0, true), 0);
        // A CPU busy with exactly one task has nr_running == 0, because the
        // picker popped it. Counting only nr_running would report that CPU as
        // idle — the bug this addition exists to avoid.
        assert_eq!(rq_active(0, false), 1);
        assert_eq!(rq_active(3, false), 4);
        // Queued work while idle-running is still counted (the wake is pending).
        assert_eq!(rq_active(2, true), 2);
    }

    #[test]
    fn calc_load_converges_toward_active() {
        // Constant load of 2 → EWMA rises from 0 toward 2.0.
        let mut l = 0u64;
        for _ in 0..200 { l = calc_load(l, EXP_1, 2); }
        let (i, _) = fmt_parts(l);
        assert!(i >= 1, "1m avg should approach 2 under sustained load, got int={i}");
    }
}
