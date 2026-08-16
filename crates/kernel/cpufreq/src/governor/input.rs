// What a governor sees and what it returns.

use crate::policy::Limits;
use crate::uapi::Relation;

/// The policy, as a governor sees it at one instant.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Limits in force, kilohertz.
    pub limits: Limits,
    /// The hardware's own range, kilohertz.
    pub hw: Limits,
    /// Frequency the policy is at, kilohertz.
    pub cur: u32,
    /// What `scaling_setspeed` last asked for, kilohertz.
    pub setspeed: Option<u32>,
}

/// Scale utilisation is measured against: a fully busy CPU reads as this.
pub const CAPACITY_SCALE: u64 = 1024;

/// The demand measured on the policy.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Demand {
    /// Busy fraction over the last sampling window, percent.
    pub load_percent: u32,
    /// Scheduler utilisation, out of `CAPACITY_SCALE`.
    pub util: u64,
    /// Capacity available on this CPU, out of `CAPACITY_SCALE`.
    pub capacity: u64,
    /// Utilisation floor contributed by the wait-for-IO boost.
    pub iowait_boost: u64,
}

/// A governor's answer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub freq_khz: u32,
    pub relation: Relation,
}

impl Target {
    /// Never slower than `freq_khz`. # C: O(1)
    pub fn at_least(freq_khz: u32) -> Target {
        Target { freq_khz, relation: Relation::Lowest }
    }
    /// Never faster than `freq_khz`. # C: O(1)
    pub fn at_most(freq_khz: u32) -> Target {
        Target { freq_khz, relation: Relation::Highest }
    }
    /// Whichever point is nearest. # C: O(1)
    pub fn nearest(freq_khz: u32) -> Target {
        Target { freq_khz, relation: Relation::Closest }
    }
}

/// Headroom applied to a utilisation figure before it becomes a frequency:
/// one quarter more than measured.
///
/// Without it a CPU that is fully busy at its current frequency asks for
/// exactly that frequency and never climbs, because the measurement is taken
/// at the frequency it is already running. The quarter is what makes an
/// eighty-percent-busy CPU ask for its maximum. # C: O(1)
pub fn with_headroom(util: u64) -> u64 { util + (util >> 2) }

/// Frequency that `util` out of `capacity` calls for, given a reference
/// frequency the utilisation was measured against. # C: O(1)
pub fn util_to_freq(util: u64, capacity: u64, reference_khz: u64) -> u32 {
    if capacity == 0 { return reference_khz as u32; }
    let scaled = reference_khz.saturating_mul(util) / capacity;
    scaled.min(u64::from(u32::MAX)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_headroom_is_a_quarter_more_than_measured() {
        assert_eq!(with_headroom(0), 0);
        assert_eq!(with_headroom(800), 1000);
        assert_eq!(with_headroom(1024), 1280);
    }

    #[test]
    fn an_eighty_percent_busy_cpu_asks_for_essentially_its_full_reference_frequency() {
        // Four fifths of capacity, plus the quarter of headroom, is the whole
        // of it bar the truncation in the fifth.
        let util = with_headroom(CAPACITY_SCALE * 4 / 5);
        let freq = util_to_freq(util, CAPACITY_SCALE, 2_400_000);
        assert!(freq > 2_390_000 && freq <= 2_400_000, "{freq}");
        // A percent more and there is nothing left to ask for.
        assert_eq!(util_to_freq(with_headroom(CAPACITY_SCALE * 4 / 5 + 11)
                       .min(CAPACITY_SCALE), CAPACITY_SCALE, 2_400_000),
                   2_400_000);
    }

    #[test]
    fn a_half_busy_cpu_asks_for_five_eighths_of_the_reference() {
        let util = with_headroom(CAPACITY_SCALE / 2);
        assert_eq!(util_to_freq(util, CAPACITY_SCALE, 1_600_000), 1_000_000);
    }

    #[test]
    fn an_idle_cpu_asks_for_nothing_and_a_zero_capacity_cannot_divide_by_it() {
        assert_eq!(util_to_freq(0, CAPACITY_SCALE, 2_400_000), 0);
        assert_eq!(util_to_freq(500, 0, 2_400_000), 2_400_000);
    }

    #[test]
    fn each_target_carries_the_direction_its_meaning_needs() {
        assert_eq!(Target::at_least(1).relation, Relation::Lowest);
        assert_eq!(Target::at_most(1).relation, Relation::Highest);
        assert_eq!(Target::nearest(1).relation, Relation::Closest);
    }
}
