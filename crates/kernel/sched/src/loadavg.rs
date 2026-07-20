//! Linux load average — EWMA of the runnable task count over 1/5/15 min,
//! resampled every ~5s (Linux `kernel/sched/loadavg.c` CALC_LOAD). Fixed-point
//! FSHIFT=11. `/proc/loadavg` reads `snapshot()`.
//!
//! `active` is the runnable task count (Linux also counts TASK_UNINTERRUPTIBLE;
//! oxide reports runnable for now). The 5s cadence is gated on the monotonic
//! clock, so it needs no knowledge of the timer-tick rate.

use core::sync::atomic::{AtomicU64, Ordering};

const FSHIFT: u32 = 11;
const SI_LOAD_SHIFT: u32 = 16;
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

fn active_count() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    { crate::live::registry::live_counts().1 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// `(1min, 5min, 15min)` load averages in FSHIFT fixed-point. # C: O(1)
pub fn snapshot() -> [u64; 3] {
    [AVENRUN[0].load(Ordering::Relaxed),
     AVENRUN[1].load(Ordering::Relaxed),
     AVENRUN[2].load(Ordering::Relaxed)]
}

/// Linux `struct sysinfo.loads` representation of the scheduler's canonical
/// fixed-point load averages (`SI_LOAD_SHIFT`, not a formatter-side scale).
/// # C: O(1)
pub fn sysinfo_snapshot() -> [u64; 3] {
    snapshot().map(|load| load << (SI_LOAD_SHIFT - FSHIFT))
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
}
