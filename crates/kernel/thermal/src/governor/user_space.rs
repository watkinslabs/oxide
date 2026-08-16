// `user_space`: the kernel measures and reports; a daemon decides. Every
// crossing is published as a class event carrying the zone, the temperature
// and the trip; no cooling device is touched from here.

use super::input::{unchanged, GovInput, Governor, Targets};

/// The governor as a zone selects it.
pub static USER_SPACE: Governor = Governor {
    name: "user_space",
    govern: user_space,
    publishes_crossings: true,
};

/// Change nothing; the crossing is published instead. # C: O(N_instances)
pub fn user_space(input: &GovInput) -> Targets { unchanged(input) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::{Trend, NO_TARGET};
    use super::super::input::InstanceView;

    #[test]
    fn no_cooling_device_is_driven_and_the_crossing_is_published() {
        let instances = alloc::vec![InstanceView {
            trip: 0, cdev_max: 4, cdev_cur: 0, upper: 4, lower: 0,
            weight: 0, target: NO_TARGET, initialized: false,
        }];
        let input = GovInput {
            temperature: 90_000, trend: Trend::Raising, trips: &[],
            instances: &instances, crossings: &[],
        };
        assert_eq!(user_space(&input), alloc::vec![None]);
        assert!(USER_SPACE.publishes_crossings);
    }
}
