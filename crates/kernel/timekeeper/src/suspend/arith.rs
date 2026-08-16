// Sleep-time arithmetic for the timekeeping core callbacks (`32a§7`, `23`).
//
// Everything here is pure. Getting it wrong makes every timeout in the system
// wrong after one suspend and nothing crashes, so the arithmetic lives apart
// from the register reads and is pinned by tests rather than by a boot.

/// A clocksource's counter shape: how wide the counter is and how its cycles
/// convert to nanoseconds.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Clocksource {
    /// Valid counter bits; a narrower counter wraps within this mask.
    pub mask: u64,
    /// Cycle-to-nanosecond numerator, applied before `shift`.
    pub mult: u32,
    /// Cycle-to-nanosecond right shift.
    pub shift: u32,
}

impl Clocksource {
    /// A counter that already reads in nanoseconds and uses its full width.
    /// # C: O(1)
    pub const fn nanoseconds() -> Self { Clocksource { mask: u64::MAX, mult: 1, shift: 0 } }

    /// Largest forward distance accepted as elapsed time rather than as the
    /// counter having moved backwards. Seven eighths of the counter range: a
    /// long sleep can legitimately pass half the range, so half is too tight.
    /// # C: O(1)
    pub const fn max_raw_delta(&self) -> u64 {
        (self.mask >> 1) + (self.mask >> 2) + (self.mask >> 3)
    }

    /// Cycle count above which the narrow multiply would overflow 64 bits.
    /// # C: O(1)
    pub const fn max_cycles(&self) -> u64 {
        if self.mult == 0 { return self.mask; }
        let by_mult = u64::MAX / self.mult as u64;
        if by_mult < self.mask { by_mult } else { self.mask }
    }
}

/// Forward distance from `start` to `now` on a counter of width `mask`.
///
/// The mask is what makes a wrapped counter work: the subtraction is modular,
/// so a counter that rolled over between the two readings still yields the
/// true distance. A result past [`Clocksource::max_raw_delta`] is the counter
/// having gone backwards, and is reported as no elapsed time rather than as
/// most of a counter period.
/// # C: O(1)
pub fn cycle_delta(cs: &Clocksource, start: u64, now: u64) -> u64 {
    let d = now.wrapping_sub(start) & cs.mask;
    if d > cs.max_raw_delta() { 0 } else { d }
}

/// Nanoseconds `delta` cycles represent. Widens the multiply once the narrow
/// one could overflow, so a long sleep converts exactly rather than wrapping.
/// # C: O(1)
pub fn cycles_to_ns(cs: &Clocksource, delta: u64) -> u64 {
    if delta < cs.max_cycles() {
        (delta * cs.mult as u64) >> cs.shift
    } else {
        let wide = (delta as u128 * cs.mult as u128) >> cs.shift;
        if wide > u64::MAX as u128 { u64::MAX } else { wide as u64 }
    }
}

/// Nanoseconds slept, from the counter reading taken at suspend and the one
/// taken at resume. # C: O(1)
pub fn sleep_ns(cs: &Clocksource, at_suspend: u64, at_resume: u64) -> u64 {
    cycles_to_ns(cs, cycle_delta(cs, at_suspend, at_resume))
}

/// How each clock moves across a sleep of `ns` (`32a§7`).
///
/// The split is the contract: `CLOCK_MONOTONIC` excludes the sleep, and
/// `CLOCK_BOOTTIME` and `CLOCK_REALTIME` include it. Naming it as data keeps
/// the three from drifting apart in three separate call sites.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SleepAccount {
    pub monotonic_ns: u64,
    pub boottime_ns: u64,
    pub realtime_ns: u64,
}

/// The per-clock advance for a sleep of `ns`. # C: O(1)
pub const fn account(ns: u64) -> SleepAccount {
    SleepAccount { monotonic_ns: 0, boottime_ns: ns, realtime_ns: ns }
}

/// Whether a resume should inject `ns` at all. A zero delta means the counter
/// never moved, which is a counter that stopped and cannot measure the sleep —
/// injecting nothing is right, inventing a duration is not.
/// # C: O(1)
pub const fn should_inject(ns: u64) -> bool { ns > 0 }
