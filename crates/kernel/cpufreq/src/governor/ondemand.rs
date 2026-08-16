// `ondemand`: sample how busy the CPU has been, jump straight to the ceiling
// once it passes a threshold, and otherwise scale linearly with the load.
//
// The asymmetry is deliberate. Going up late costs latency on every request
// that arrives while the CPU is still slow, so the climb is a jump; coming
// down early costs a second climb, so the descent is gradual.

use super::input::{Demand, Snapshot, Target};

/// Load at which the governor stops interpolating and goes to the ceiling.
pub const UP_THRESHOLD_PERCENT: u32 = 80;
/// Smallest threshold a tunable write may set.
pub const MIN_UP_THRESHOLD_PERCENT: u32 = 1;
/// Largest threshold a tunable write may set.
pub const MAX_UP_THRESHOLD_PERCENT: u32 = 100;
/// Full load.
pub const FULL_LOAD_PERCENT: u32 = 100;
/// How much longer the governor waits between samples while pinned at the
/// ceiling, by default.
pub const SAMPLING_DOWN_FACTOR: u32 = 1;
/// Largest sampling-down factor a tunable write may set.
pub const MAX_SAMPLING_DOWN_FACTOR: u32 = 100_000;

/// Busy fraction of one sampling window, percent. A window in which no time
/// passed carries no information and reports zero rather than dividing by it.
/// # C: O(1)
pub fn load_percent(elapsed_ns: u64, idle_ns: u64) -> u32 {
    if elapsed_ns == 0 || idle_ns >= elapsed_ns { return 0; }
    let busy = elapsed_ns - idle_ns;
    (busy.saturating_mul(u64::from(FULL_LOAD_PERCENT)) / elapsed_ns) as u32
}

/// The tunables one policy runs with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Tunables {
    pub up_threshold_percent: u32,
    pub sampling_rate_us: u64,
    pub sampling_down_factor: u32,
    /// Whether time spent waiting on a device counts as busy.
    pub io_is_busy: bool,
}

impl Tunables {
    /// Tunables derived from the driver's declared transition latency.
    /// # C: O(1)
    pub fn from_latency(transition_latency_ns: u64) -> Tunables {
        Tunables {
            up_threshold_percent: UP_THRESHOLD_PERCENT,
            sampling_rate_us: crate::limits::transition_delay_us(transition_latency_ns),
            sampling_down_factor: SAMPLING_DOWN_FACTOR,
            io_is_busy: false,
        }
    }

    /// Apply a threshold write, refusing one outside the usable range.
    /// # C: O(1)
    pub fn set_up_threshold(&mut self, percent: u32) -> bool {
        if !(MIN_UP_THRESHOLD_PERCENT..=MAX_UP_THRESHOLD_PERCENT).contains(&percent) {
            return false;
        }
        self.up_threshold_percent = percent;
        true
    }
}

/// Choose a target from the measured load.
///
/// Above the threshold: the ceiling. Below it: a point on the line between the
/// hardware's own floor and ceiling, not the policy's — the load is a property
/// of the processor, and interpolating across a narrowed range would make the
/// same load ask for a different fraction of the machine every time a cap
/// moved. The result is then held inside the policy limits by the resolution.
/// # C: O(1)
pub fn ondemand(snapshot: &Snapshot, demand: &Demand, tunables: &Tunables) -> Option<Target> {
    if demand.load_percent > tunables.up_threshold_percent {
        return Some(Target::at_most(snapshot.limits.max));
    }
    let span = u64::from(snapshot.hw.max.saturating_sub(snapshot.hw.min));
    let step = span.saturating_mul(u64::from(demand.load_percent))
        / u64::from(FULL_LOAD_PERCENT);
    let target = u64::from(snapshot.hw.min).saturating_add(step);
    Some(Target::nearest(target.min(u64::from(u32::MAX)) as u32))
}

/// The default tunables, for a policy whose driver declared no latency.
/// # C: O(1)
pub fn default_tunables() -> Tunables {
    Tunables::from_latency(crate::limits::DEFAULT_TRANSITION_LATENCY_NS)
}

#[cfg(test)]
#[path = "../tests/ondemand.rs"]
mod tests;
