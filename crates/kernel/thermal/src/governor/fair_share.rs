// `fair_share`: state proportional to how far into the trip ladder the zone
// has climbed, divided between the bound cooling devices by their weights. A
// zone with several ways to cool itself spreads the work instead of saturating
// the first device bound to it.

use super::input::{GovInput, Governor, Targets};

/// The governor as a zone selects it.
pub static FAIR_SHARE: Governor = Governor {
    name: "fair_share",
    govern: fair_share,
    publishes_crossings: false,
};

/// How many governed trips the zone has climbed past. # C: O(N_trips)
pub fn trip_level(input: &GovInput) -> u64 {
    input.trips.iter()
        .filter(|desc| desc.trip.ty.governed())
        .filter(|desc| desc.threshold().is_some_and(|t| t <= input.temperature))
        .count() as u64
}

/// Share every bound device by weight, scaled by how deep into the ladder the
/// zone is. With no weights declared the devices split the work evenly.
/// # C: O(N_trips + N_instances)
pub fn fair_share(input: &GovInput) -> Targets {
    let level = trip_level(input);
    let governed = input.trips.iter().filter(|d| d.trip.ty.governed()).count() as u64;
    if governed == 0 { return super::input::unchanged(input); }
    let total_weight: u64 = input.instances.iter().map(|i| u64::from(i.weight)).sum();
    let instances = input.instances.len() as u64;
    input.instances.iter().map(|instance| {
        let trip = input.trips.get(instance.trip)?;
        if !trip.trip.ty.governed() || !trip.trip.valid() { return None; }
        let (numerator, denominator) = if total_weight == 0 {
            (level * instance.cdev_max, governed * instances)
        } else {
            (level * instance.cdev_max * u64::from(instance.weight), governed * total_weight)
        };
        if denominator == 0 { return None; }
        Some(instance.clamp(numerator / denominator))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trip::{Trip, TripDesc};
    use crate::uapi::{Trend, TripType, NO_TARGET};
    use super::super::input::InstanceView;

    fn view(trip: usize, weight: u32) -> InstanceView {
        InstanceView {
            trip, cdev_max: 10, cdev_cur: 0, upper: 10, lower: 0,
            weight, target: NO_TARGET, initialized: true,
        }
    }

    fn trips() -> alloc::vec::Vec<TripDesc> {
        let mut trips = alloc::vec![
            TripDesc::new(Trip::new(TripType::Active, 50_000)),
            TripDesc::new(Trip::new(TripType::Active, 70_000)),
        ];
        for desc in trips.iter_mut() { let _ = desc; }
        trips
    }

    #[test]
    fn a_cool_zone_asks_for_nothing() {
        let trips = trips();
        let instances = alloc::vec![view(0, 0), view(1, 0)];
        let input = GovInput {
            temperature: 20_000, trend: Trend::Stable, trips: &trips,
            instances: &instances, crossings: &[],
        };
        assert_eq!(trip_level(&input), 0);
        assert_eq!(fair_share(&input), alloc::vec![Some(0), Some(0)]);
    }

    #[test]
    fn unweighted_devices_split_the_ladder_evenly() {
        let trips = trips();
        let instances = alloc::vec![view(0, 0), view(1, 0)];
        let input = GovInput {
            temperature: 75_000, trend: Trend::Stable, trips: &trips,
            instances: &instances, crossings: &[],
        };
        assert_eq!(trip_level(&input), 2);
        // 2 * 10 / (2 trips * 2 instances) = 5 each.
        assert_eq!(fair_share(&input), alloc::vec![Some(5), Some(5)]);
    }

    #[test]
    fn a_heavier_weight_takes_a_larger_share() {
        let trips = trips();
        let instances = alloc::vec![view(0, 3), view(1, 1)];
        let input = GovInput {
            temperature: 75_000, trend: Trend::Stable, trips: &trips,
            instances: &instances, crossings: &[],
        };
        // 2 * 10 * 3 / (2 * 4) = 7 and 2 * 10 * 1 / (2 * 4) = 2.
        assert_eq!(fair_share(&input), alloc::vec![Some(7), Some(2)]);
    }
}
