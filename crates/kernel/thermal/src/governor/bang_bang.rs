// `bang_bang`: the cooling device is on above the trip and off below the
// bottom of its hysteresis band, with nothing in between. Correct for a fan
// that has one speed; the whole hysteresis band is what stops it chattering,
// and it lives in the crossing detection rather than here.

use super::input::{GovInput, Governor, Targets};

/// The governor as a zone selects it.
pub static BANG_BANG: Governor = Governor {
    name: "bang_bang",
    govern: bang_bang,
    publishes_crossings: false,
};

/// Cooling device off.
pub const OFF: u64 = 0;
/// Cooling device on.
pub const ON: u64 = 1;

/// Drive every binding to on or off from whether its trip is reached.
///
/// A binding the governor has never assigned is pushed unconditionally, which
/// is what synchronises a device bound after the zone was already hot: with no
/// crossing to react to, an already-reached trip would otherwise leave its
/// newly bound fan off. # C: O(N_instances)
pub fn bang_bang(input: &GovInput) -> Targets {
    input.instances.iter().map(|instance| {
        let Some(trip) = input.trips.get(instance.trip) else { return None; };
        if !trip.trip.ty.governed() || !trip.trip.valid() { return None; }
        let on = input.throttling(instance);
        let crossed = input.crossings.iter().any(|c| c.index == instance.trip);
        if !crossed && instance.initialized { return None; }
        Some(if on { ON } else { OFF })
    }).collect()
}

#[cfg(test)]
#[path = "../tests/bang_bang.rs"]
mod tests;
