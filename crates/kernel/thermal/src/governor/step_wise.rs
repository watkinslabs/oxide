// `step_wise`: move each cooling device one state per sample, in the
// direction the temperature is going. Converges on the shallowest state that
// holds the zone, rather than jumping to full cooling on the first sample.

use crate::uapi::{Trend, NO_TARGET};

use super::input::{GovInput, Governor, InstanceView, Targets};

/// The governor as a zone selects it.
pub static STEP_WISE: Governor = Governor {
    name: "step_wise",
    govern: step_wise,
    publishes_crossings: false,
};

/// Decide one binding's next state.
///
/// The table, with `cur` the device's current state:
///
/// | throttling | trend    | target                       |
/// |---|---|---|
/// | first pass, yes | any      | `clamp(cur + 1)`        |
/// | first pass, no  | any      | none requested          |
/// | yes        | raising  | `clamp(cur + 1)`             |
/// | yes        | dropping | `clamp(cur - 1)`, floor `lower + 1` |
/// | yes        | stable   | unchanged                    |
/// | no         | dropping | `lower`, or none once at it   |
/// | no         | raising or stable | unchanged           |
///
/// The raised floor while throttling is the point: a trip that is still above
/// its threshold must not be allowed to release its cooling device entirely
/// just because the temperature ticked down once. Full release happens only on
/// the path where the trip is no longer asking for cooling at all. # C: O(1)
fn target_state(instance: &InstanceView, trend: Trend, throttling: bool) -> Option<u64> {
    let cur = instance.cdev_cur;
    if !instance.initialized {
        return Some(if throttling { instance.clamp(cur.saturating_add(1)) } else { NO_TARGET });
    }
    if throttling {
        return match trend {
            Trend::Raising => Some(instance.clamp(cur.saturating_add(1))),
            Trend::Dropping => {
                let floor = instance.lower.saturating_add(1).min(instance.upper);
                Some(cur.saturating_sub(1).clamp(floor, instance.upper))
            }
            Trend::Stable => None,
        };
    }
    if trend == Trend::Dropping {
        return Some(if cur <= instance.lower { NO_TARGET } else { instance.lower });
    }
    None
}

/// Step every binding of the zone. # C: O(N_instances)
pub fn step_wise(input: &GovInput) -> Targets {
    input.instances.iter().map(|instance| {
        let Some(trip) = input.trips.get(instance.trip) else { return None; };
        if !trip.trip.ty.governed() || !trip.trip.valid() { return None; }
        target_state(instance, input.trend, input.throttling(instance))
    }).collect()
}

#[cfg(test)]
#[path = "../tests/step_wise.rs"]
mod tests;
