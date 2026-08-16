// The snapshot a governor decides from, and the shape of a governor.

use alloc::vec::Vec;

use crate::trip::TripDesc;
use crate::uapi::{Trend, NO_TARGET};
use crate::update::Crossing;

/// One zone-to-cooling-device binding, as the governor sees it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InstanceView {
    /// Index of the trip this binding cools.
    pub trip: usize,
    /// Deepest state the cooling device supports.
    pub cdev_max: u64,
    /// State the cooling device is in right now.
    pub cdev_cur: u64,
    /// Deepest state this binding may ask for.
    pub upper: u64,
    /// Shallowest state this binding may ask for.
    pub lower: u64,
    /// Share of this binding when several cool the same zone.
    pub weight: u32,
    /// State this binding currently asks for, or `NO_TARGET`.
    pub target: u64,
    /// Whether the governor has ever assigned this binding a target.
    pub initialized: bool,
}

impl InstanceView {
    /// Clamp a candidate state into the range this binding was bound with.
    /// # C: O(1)
    pub fn clamp(&self, state: u64) -> u64 { state.clamp(self.lower, self.upper) }
}

/// Everything a governor is allowed to look at.
pub struct GovInput<'a> {
    /// Current zone temperature, millidegrees Celsius.
    pub temperature: i32,
    /// Direction the temperature is moving.
    pub trend: Trend,
    /// Every declared trip, with its current crossing state.
    pub trips: &'a [TripDesc],
    /// Every binding of this zone, in instance order.
    pub instances: &'a [InstanceView],
    /// Crossings detected by the reading that triggered this pass.
    pub crossings: &'a [Crossing],
}

impl GovInput<'_> {
    /// The temperature at which the governed trip behind `instance` next
    /// changes state. A trip already reached compares against the bottom of
    /// its hysteresis band, which is what keeps a governor from releasing a
    /// cooling device the moment the temperature dips. # C: O(1)
    pub fn threshold_of(&self, instance: &InstanceView) -> Option<i32> {
        self.trips.get(instance.trip)?.threshold()
    }

    /// Whether the trip behind `instance` is asking for cooling. # C: O(1)
    pub fn throttling(&self, instance: &InstanceView) -> bool {
        self.threshold_of(instance).is_some_and(|threshold| self.temperature >= threshold)
    }
}

/// A governor's decision: one entry per instance, in instance order. `None`
/// leaves the binding's target alone.
pub type Targets = Vec<Option<u64>>;

/// The policy half of a zone.
pub struct Governor {
    /// Name as `policy` reads it back and `available_policies` lists it.
    pub name: &'static str,
    /// Decide every binding's target from one snapshot.
    pub govern: fn(&GovInput) -> Targets,
    /// Whether a crossing under this governor is published to userspace
    /// instead of being cooled here.
    pub publishes_crossings: bool,
}

/// A decision that leaves every binding alone. # C: O(N_instances)
pub fn unchanged(input: &GovInput) -> Targets {
    alloc::vec![None; input.instances.len()]
}

/// Whether a target list actually moves anything. # C: O(N_instances)
pub fn any_change(input: &GovInput, targets: &[Option<u64>]) -> bool {
    input.instances.iter().zip(targets).any(|(instance, target)| match target {
        None => false,
        Some(state) => !instance.initialized || *state != instance.target,
    })
}

/// The state a cooling device must be driven to when several bindings ask for
/// different ones: the deepest of them. A shallower request cannot be honoured
/// while another zone still needs the deeper one. # C: O(N)
pub fn aggregate(targets: impl Iterator<Item = u64>) -> u64 {
    let mut state = 0;
    for target in targets {
        if target == NO_TARGET { continue; }
        if target > state { state = target; }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_clamps_a_candidate_into_its_bound_range() {
        let instance = InstanceView {
            trip: 0, cdev_max: 10, cdev_cur: 0, upper: 7, lower: 2,
            weight: 0, target: NO_TARGET, initialized: false,
        };
        assert_eq!(instance.clamp(0), 2);
        assert_eq!(instance.clamp(5), 5);
        assert_eq!(instance.clamp(9), 7);
    }

    #[test]
    fn the_deepest_request_wins_and_no_request_counts_as_off() {
        assert_eq!(aggregate([NO_TARGET, NO_TARGET].into_iter()), 0);
        assert_eq!(aggregate([1, 4, 2].into_iter()), 4);
        assert_eq!(aggregate([NO_TARGET, 3, NO_TARGET].into_iter()), 3);
        assert_eq!(aggregate(core::iter::empty()), 0);
    }

    #[test]
    fn a_first_assignment_counts_as_a_change_even_at_the_same_value() {
        let instances = alloc::vec![InstanceView {
            trip: 0, cdev_max: 1, cdev_cur: 0, upper: 1, lower: 0,
            weight: 0, target: 0, initialized: false,
        }];
        let input = GovInput {
            temperature: 0, trend: Trend::Stable, trips: &[],
            instances: &instances, crossings: &[],
        };
        assert!(any_change(&input, &[Some(0)]),
                "an uninitialized binding must be pushed to the device once");
        assert!(!any_change(&input, &[None]));
    }
}
