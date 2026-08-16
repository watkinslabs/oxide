// The three governors that measure nothing: run as fast as allowed, run as
// slowly as allowed, or run at whatever userspace last wrote.

use super::input::{Demand, Snapshot, Target};

/// Always the ceiling. # C: O(1)
pub fn performance(snapshot: &Snapshot, _demand: &Demand) -> Option<Target> {
    Some(Target::at_most(snapshot.limits.max))
}

/// Always the floor. # C: O(1)
pub fn powersave(snapshot: &Snapshot, _demand: &Demand) -> Option<Target> {
    Some(Target::at_least(snapshot.limits.min))
}

/// What `scaling_setspeed` asked for, held inside the limits in force.
///
/// Re-clamped on every pass rather than only when written: a thermal cap that
/// arrives after the write must pull the requested frequency down, and a cap
/// that lifts must let it back up without userspace having to write again.
/// # C: O(1)
pub fn userspace(snapshot: &Snapshot, _demand: &Demand) -> Option<Target> {
    let asked = snapshot.setspeed?;
    if asked > snapshot.limits.max { return Some(Target::at_most(snapshot.limits.max)); }
    if asked < snapshot.limits.min { return Some(Target::at_least(snapshot.limits.min)); }
    Some(Target::at_least(asked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Limits;
    use crate::uapi::Relation;

    fn snapshot(setspeed: Option<u32>) -> Snapshot {
        Snapshot {
            limits: Limits { min: 1_200_000, max: 1_800_000 },
            hw: Limits { min: 800_000, max: 2_400_000 },
            cur: 1_200_000,
            setspeed,
        }
    }

    #[test]
    fn the_fastest_governor_asks_for_the_ceiling_in_force_not_the_hardware_one() {
        let target = performance(&snapshot(None), &Demand::default()).expect("target");
        assert_eq!(target.freq_khz, 1_800_000);
        assert_eq!(target.relation, Relation::Highest);
    }

    #[test]
    fn the_slowest_governor_asks_for_the_floor_in_force() {
        let target = powersave(&snapshot(None), &Demand::default()).expect("target");
        assert_eq!(target.freq_khz, 1_200_000);
        assert_eq!(target.relation, Relation::Lowest);
    }

    #[test]
    fn the_manual_governor_asks_for_nothing_until_something_is_written() {
        assert_eq!(userspace(&snapshot(None), &Demand::default()), None);
    }

    #[test]
    fn a_written_speed_is_honoured_inside_the_limits() {
        let target = userspace(&snapshot(Some(1_500_000)), &Demand::default()).expect("target");
        assert_eq!(target.freq_khz, 1_500_000);
    }

    #[test]
    fn a_written_speed_outside_the_limits_is_pulled_back_every_pass() {
        let high = userspace(&snapshot(Some(2_400_000)), &Demand::default()).expect("target");
        assert_eq!(high.freq_khz, 1_800_000);
        assert_eq!(high.relation, Relation::Highest,
                   "a cap must not be exceeded by rounding up to the nearest point");

        let low = userspace(&snapshot(Some(800_000)), &Demand::default()).expect("target");
        assert_eq!(low.freq_khz, 1_200_000);
        assert_eq!(low.relation, Relation::Lowest);
    }
}
