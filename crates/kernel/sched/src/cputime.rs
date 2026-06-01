// CFS CPU-time accounting primitives per `13§3`. Pure functions —
// hosted-tested — that the live `update_curr` path composes with the
// monotonic clock. Foundation for nice-weighted fairness and the
// cgroup v2 cpu controller (cpu.weight / cpu.max).

/// CFS weight of a nice-0 task (`sched_prio_to_weight[20]` in Linux).
/// vruntime advances as `delta_exec · NICE_0_WEIGHT / weight`, so a
/// nice-0 task accrues vruntime at exactly wall-clock rate.
pub const NICE_0_WEIGHT: u32 = 1024;

/// Linux `sched_prio_to_weight[]` (kernel/sched/core.c): nice -20..19 →
/// load weight. Each nice step is ~1.25× CPU share. Index = nice + 20.
pub const SCHED_PRIO_TO_WEIGHT: [u32; 40] = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */  9548,  7620,  6100,  4904,  3906,
    /*  -5 */  3121,  2501,  1991,  1586,  1277,
    /*   0 */  1024,   820,   655,   526,   423,
    /*   5 */   335,   272,   215,   172,   137,
    /*  10 */   110,    87,    70,    56,    45,
    /*  15 */    36,    29,    23,    18,    15,
];

/// Nice value [-20,19] → CFS load weight. Out-of-range clamps.
/// # C: O(1)
pub fn nice_to_weight(nice: i8) -> u32 {
    let idx = (nice as i32 + 20).clamp(0, 39) as usize;
    SCHED_PRIO_TO_WEIGHT[idx]
}

/// vruntime increment for `delta_exec_ns` of CPU time at `weight`.
/// `delta · NICE_0_WEIGHT / weight`: heavier tasks (higher weight, more
/// negative nice) accrue vruntime slower → get scheduled more. Computed
/// in u128 to avoid overflow on large deltas, saturated back to u64.
/// A zero or absurd weight falls back to NICE_0 so we never divide by 0.
/// # C: O(1)
pub fn vruntime_delta(delta_exec_ns: u64, weight: u32) -> u64 {
    let w = if weight == 0 { NICE_0_WEIGHT } else { weight } as u128;
    let scaled = (delta_exec_ns as u128) * (NICE_0_WEIGHT as u128) / w;
    scaled.min(u64::MAX as u128) as u64
}

/// Clamp a raw `now - exec_start` delta. A backwards or implausibly
/// large jump (clock skew, first-run sentinel, migration) is treated as
/// a single tick's worth so accounting can't spike. `max_tick_ns` is the
/// scheduler tick period (the largest sane single-charge).
/// # C: O(1)
pub fn clamp_delta(now_ns: u64, exec_start_ns: u64, max_tick_ns: u64) -> u64 {
    if now_ns <= exec_start_ns { return 0; }
    (now_ns - exec_start_ns).min(max_tick_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nice_0_is_wall_rate() {
        // nice 0 → weight 1024 → vruntime advances 1:1 with wall time.
        assert_eq!(nice_to_weight(0), NICE_0_WEIGHT);
        assert_eq!(vruntime_delta(1_000_000, NICE_0_WEIGHT), 1_000_000);
    }

    #[test]
    fn lower_nice_accrues_vruntime_slower() {
        // nice -20 (heavy) accrues far less vruntime than nice 0 for the
        // same CPU time → picked more often.
        let heavy = nice_to_weight(-20);
        let light = nice_to_weight(19);
        assert!(heavy > NICE_0_WEIGHT && light < NICE_0_WEIGHT);
        let d = 10_000_000u64;
        assert!(vruntime_delta(d, heavy) < vruntime_delta(d, NICE_0_WEIGHT));
        assert!(vruntime_delta(d, light) > vruntime_delta(d, NICE_0_WEIGHT));
    }

    #[test]
    fn nice_clamps_and_table_bounds() {
        assert_eq!(nice_to_weight(-20), 88761);
        assert_eq!(nice_to_weight(19), 15);
        assert_eq!(nice_to_weight(-128), nice_to_weight(-20)); // clamp lo
        assert_eq!(nice_to_weight(127), nice_to_weight(19));   // clamp hi
    }

    #[test]
    fn vruntime_delta_never_divides_by_zero() {
        assert_eq!(vruntime_delta(1_000, 0), 1_000); // falls back to NICE_0
    }

    #[test]
    fn vruntime_delta_no_overflow() {
        // Huge delta · heavy weight stays finite.
        let v = vruntime_delta(u64::MAX, nice_to_weight(-20));
        assert!(v > 0 && v <= u64::MAX);
    }

    #[test]
    fn clamp_delta_handles_skew() {
        let tick = 10_000_000u64;
        assert_eq!(clamp_delta(100, 100, tick), 0);   // no progress
        assert_eq!(clamp_delta(50, 100, tick), 0);    // backwards
        assert_eq!(clamp_delta(105, 100, tick), 5);   // normal
        assert_eq!(clamp_delta(1 << 40, 0, tick), tick); // huge → one tick
    }
}
