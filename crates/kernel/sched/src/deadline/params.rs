// SCHED_DEADLINE static parameters: the triple userspace supplies
// (`sched_runtime`, `sched_deadline`, `sched_period`), the fixed-point
// bandwidth pair derived from it, and the validation ladder.
//
// Ungated on purpose. The whole point of a deadline class is arithmetic —
// a bandwidth that is off by a shift admits a task set the CPU cannot run —
// and arithmetic that lives inside a `target_os` -gated file has no tests
// (`08§7`, the phantom-test rule).

/// Fixed-point shift for a bandwidth ratio: a utilization of 1.0 is `1 << 20`.
pub const BW_SHIFT: u32 = 20;
/// Bandwidth unit — utilization 1.0 (100% of one CPU).
pub const BW_UNIT: u64 = 1 << BW_SHIFT;
/// Secondary shift used by the reclaim (GRUB) ratio.
pub const RATIO_SHIFT: u32 = 8;
/// Largest representable bandwidth numerator: `runtime << BW_SHIFT` must not
/// overflow `u64`, so a runtime at or above `1 << (64 - BW_SHIFT)` is refused.
pub const MAX_BW: u64 = (1u64 << (64 - BW_SHIFT)) - 1;
/// Bits the admission/overflow arithmetic truncates before multiplying, so the
/// products stay inside 64 bits. Also the floor on `sched_runtime`.
pub const DL_SCALE: u32 = 10;
/// Minimum admissible period, ns (the `sched_deadline_period_min_us` default).
pub const DL_PERIOD_MIN_NS: u64 = 100 * 1_000;
/// Maximum admissible period, ns (the `sched_deadline_period_max_us` default).
pub const DL_PERIOD_MAX_NS: u64 = (1u64 << 22) * 1_000;

/// `SCHED_FLAG_RECLAIM` — charge budget through the reclaim ratio instead of
/// wall time, so a task may use bandwidth other deadline tasks left idle.
pub const FLAG_RECLAIM: u64 = 0x02;
/// `SCHED_FLAG_DL_OVERRUN` — latch an overrun so a `SIGXCPU` is raised.
pub const FLAG_DL_OVERRUN: u64 = 0x04;
/// Kernel-internal frequency-governor entity flag. Bypasses parameter
/// validation and bandwidth accounting; refused from any syscall.
pub const FLAG_SUGOV: u64 = 0x1000_0000;
/// The subset of `sched_flags` that is stored on the deadline entity.
pub const SCHED_DL_FLAGS: u64 = FLAG_RECLAIM | FLAG_DL_OVERRUN | FLAG_SUGOV;

/// The static per-instance reservation of one deadline entity.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DlParams {
    /// Budget granted at each period start, ns.
    pub runtime: u64,
    /// Relative deadline of an instance, ns.
    pub deadline: u64,
    /// Inter-arrival separation of instances, ns.
    pub period: u64,
    /// `runtime / period` in `BW_SHIFT` fixed point — what admission sums.
    pub bw: u64,
    /// `runtime / deadline` in `BW_SHIFT` fixed point — what the revised-wakeup
    /// rule scales laxity by.
    pub density: u64,
    /// `SCHED_DL_FLAGS` subset of the request's `sched_flags`.
    pub flags: u64,
}

/// Utilization of `runtime` within `period`, in `BW_SHIFT` fixed point.
/// Truncating division: a reservation is never rounded UP into more bandwidth
/// than it asked for.
/// # C: O(1)
pub fn to_ratio(period: u64, runtime: u64) -> u64 {
    if runtime == u64::MAX { return BW_UNIT; }
    if period == 0 { return 0; }
    (runtime << BW_SHIFT) / period
}

impl DlParams {
    /// Build the static reservation from a validated request. A zero
    /// `sched_period` means "period equals the relative deadline", and the
    /// defaulting happens BEFORE `bw` is derived — deriving it first would
    /// record bandwidth 0 for every implicit-deadline task and admit an
    /// unbounded number of them.
    /// # C: O(1)
    pub fn from_request(runtime: u64, deadline: u64, period: u64, flags: u64) -> DlParams {
        let period = if period == 0 { deadline } else { period };
        DlParams {
            runtime, deadline, period,
            bw: to_ratio(period, runtime),
            density: to_ratio(deadline, runtime),
            flags: flags & SCHED_DL_FLAGS,
        }
    }

    /// Implicit-deadline entity: relative deadline equals the period. The
    /// original CBS rules are exact only for this shape; a constrained
    /// (`deadline < period`) entity takes the revised wakeup rule instead.
    /// # C: O(1)
    pub fn is_implicit(&self) -> bool { self.deadline == self.period }

    /// A parameter-less governor entity — never consumes budget, never
    /// accounted, always wins a deadline comparison.
    /// # C: O(1)
    pub fn is_special(&self) -> bool { self.flags & FLAG_SUGOV != 0 }

    /// Does this entity want a `SIGXCPU` when it overruns?
    /// # C: O(1)
    pub fn wants_overrun_signal(&self) -> bool { self.flags & FLAG_DL_OVERRUN != 0 }

    /// Does this entity charge its budget through the reclaim ratio?
    /// # C: O(1)
    pub fn reclaims(&self) -> bool { self.flags & FLAG_RECLAIM != 0 }
}

/// Parameter validation for a `SCHED_DEADLINE` request, in the order the
/// contract states it. `true` = acceptable; the caller answers `EINVAL`.
///
/// A `sched_param`-shaped `sched_setscheduler(2)` leaves the whole triple zero,
/// so it can never satisfy this — which is why asking for `SCHED_DEADLINE`
/// through slot 144 is `EINVAL` and not `EOPNOTSUPP` or a silent success.
/// # C: O(1)
pub fn checkparam_dl(runtime: u64, deadline: u64, period: u64, flags: u64) -> bool {
    // A governor entity carries no parameters at all and skips the ladder.
    if flags & FLAG_SUGOV != 0 { return true; }
    if deadline == 0 { return false; }
    // Below the truncation floor the overflow arithmetic reads the runtime as
    // zero, so such a reservation would be admitted at bandwidth 0.
    if runtime < (1u64 << DL_SCALE) { return false; }
    // The high bit is reserved for the wrap-safe signed deadline comparisons.
    if deadline & (1u64 << 63) != 0 || period & (1u64 << 63) != 0 { return false; }
    let period = if period == 0 { deadline } else { period };
    if period < deadline || deadline < runtime { return false; }
    if period < DL_PERIOD_MIN_NS || period > DL_PERIOD_MAX_NS { return false; }
    true
}

#[cfg(test)]
#[path = "tests/params.rs"] mod tests;
