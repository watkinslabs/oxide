// CFS CPU-time accounting primitives per `13§3`. Pure functions —
// hosted-tested — that the live `update_curr` path composes with the
// monotonic clock. Foundation for nice-weighted fairness and the
// cgroup v2 cpu controller (cpu.weight / cpu.max).

use crate::task::LoadWeight;

/// User-facing CFS weight of a nice-0 task.
pub const NICE_0_WEIGHT: u32 = 1024;

/// Internal 64-bit fair load of a nice-0 task.
pub const NICE_0_LOAD: u64 = match LoadWeight::for_nice(0) {
    Some(load) => load.weight,
    None => 0,
};

/// Nice value [-20,19] → CFS load weight. Out-of-range clamps.
/// # C: O(1)
pub fn nice_to_weight(nice: i8) -> u32 {
    let nice = (nice as i32).clamp(-20, 19) as i8;
    let load = LoadWeight::for_nice(nice).unwrap().weight;
    (load * NICE_0_WEIGHT as u64 / NICE_0_LOAD) as u32
}

/// vruntime increment for `delta_exec_ns` at canonical scaled `load`.
/// `delta · NICE_0_LOAD / load`: heavier tasks (higher load, more
/// negative nice) accrue vruntime slower → get scheduled more. Computed
/// in u128 to avoid overflow on large deltas, saturated back to u64.
/// A zero load falls back to NICE_0_LOAD so we never divide by 0.
/// # C: O(1)
pub fn vruntime_delta(delta_exec_ns: u64, load: u64) -> u64 {
    let load = if load == 0 { NICE_0_LOAD } else { load } as u128;
    let scaled = (delta_exec_ns as u128) * (NICE_0_LOAD as u128) / load;
    scaled.min(u64::MAX as u128) as u64
}

/// Return the complete positive `now - exec_start` interval.
/// Equal stamps carry no elapsed time; a backwards stamp is rejected instead
/// of wrapping. The scheduler stamps a task when it starts running, so a
/// zeroed pair is the uninitialised case and also returns zero.
/// # C: O(1)
pub fn runtime_delta(now_ns: u64, exec_start_ns: u64) -> u64 {
    if exec_start_ns == 0 { return 0; }
    now_ns.checked_sub(exec_start_ns).unwrap_or(0)
}

/// Whether a class charges scheduler runtime for the time its tasks run.
///
/// Fair, RT and deadline all do — they share one accounting helper upstream,
/// and `CLOCK_THREAD_CPUTIME_ID` / `CLOCK_PROCESS_CPUTIME_ID` sample the total
/// it maintains, so a class that skipped the charge would report a frozen CPU
/// clock to every thread in it. Only the per-CPU idle class runs unaccounted.
/// # C: O(1)
pub fn accounts_exec_runtime(class: crate::task::SchedClass) -> bool {
    !matches!(class, crate::task::SchedClass::Idle)
}

/// Fold one elapsed slice into the task's scheduler-runtime total AND its
/// thread group's, in one place so the two can never disagree — the pair a
/// per-thread and a process-wide CPU clock respectively sample.
///
/// Every accounting class routes its charge through here, from exactly one
/// site each, which is what keeps a slice from being counted twice.
/// # C: O(1)
/// # Ctx: scheduler / timer IRQ
pub fn charge_exec_runtime(task: &crate::Task, delta_ns: u64) {
    use core::sync::atomic::Ordering;
    task.sched.se.sum_exec_runtime.fetch_add(delta_ns, Ordering::Relaxed);
    task.thread_group.charge_sched_runtime(delta_ns);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nice_0_is_wall_rate() {
        // nice 0 → weight 1024 → vruntime advances 1:1 with wall time.
        assert_eq!(nice_to_weight(0), NICE_0_WEIGHT);
        assert_eq!(NICE_0_LOAD, 1_024 << 10);
        assert_eq!(vruntime_delta(1_000_000, NICE_0_LOAD), 1_000_000);
    }

    #[test]
    fn lower_nice_accrues_vruntime_slower() {
        // nice -20 (heavy) accrues far less vruntime than nice 0 for the
        // same CPU time → picked more often.
        let heavy = LoadWeight::for_nice(-20).unwrap().weight;
        let light = LoadWeight::for_nice(19).unwrap().weight;
        assert!(heavy > NICE_0_LOAD && light < NICE_0_LOAD);
        let d = 10_000_000u64;
        assert!(vruntime_delta(d, heavy) < vruntime_delta(d, NICE_0_LOAD));
        assert!(vruntime_delta(d, light) > vruntime_delta(d, NICE_0_LOAD));
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
        let load = LoadWeight::for_nice(-20).unwrap().weight;
        let v = vruntime_delta(u64::MAX, load);
        assert!(v > 0 && v <= u64::MAX);
    }

    #[test]
    fn vruntime_uses_scaled_load_without_narrowing() {
        let delta = 1_000_000u64;
        let load = LoadWeight::for_nice(0).unwrap().weight;
        assert_eq!(vruntime_delta(delta, load), delta);
        assert_ne!(vruntime_delta(delta, nice_to_weight(0) as u64), delta);
        assert_eq!(vruntime_delta(delta, u64::MAX), 0);
    }

    #[test]
    fn runtime_delta_keeps_every_positive_nanosecond() {
        assert_eq!(runtime_delta(0, 0), 0);
        assert_eq!(runtime_delta(100, 100), 0);
        assert_eq!(runtime_delta(50, 100), 0);
        assert_eq!(runtime_delta(105, 100), 5);
        assert_eq!(runtime_delta(1 << 40, 0), 0);
        assert_eq!(runtime_delta((1 << 40) + 1, 1), 1 << 40);
    }

    /// Restricting the charge to the fair class froze every SCHED_FIFO /
    /// SCHED_RR / SCHED_DEADLINE thread's CPU clock at zero, because those
    /// clocks sample the scheduler-runtime total this decision gates.
    #[test]
    fn every_class_but_idle_charges_scheduler_runtime() {
        use crate::task::{SchedClass, SchedPolicy};
        assert!(accounts_exec_runtime(SchedClass::Normal { weight: NICE_0_WEIGHT }));
        assert!(accounts_exec_runtime(SchedClass::Deadline));
        assert!(accounts_exec_runtime(SchedClass::Rt { prio: 1, policy: SchedPolicy::Fifo }));
        assert!(accounts_exec_runtime(SchedClass::Rt { prio: 99, policy: SchedPolicy::Rr }));
        assert!(!accounts_exec_runtime(SchedClass::Idle), "the idle task runs unaccounted");
    }
}
