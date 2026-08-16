// One update of one zone: read the sensor, reclassify the trips, let the
// governor decide, apply, and re-arm the poll.
//
// Provider calls happen with no lock held. A cooling device backed by firmware
// evaluates AML to change state and a sensor read can block, so the pass reads
// what it needs, decides under the lock, and applies afterwards.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::cdev::CoolingDevice;
use crate::governor::input::{any_change, GovInput};
use crate::monitor::{next_delay_ms, on_read_failure, Recheck};
use crate::limits::{NSEC_PER_MSEC, RECHECK_DELAY_MS};
use crate::trip::Bucket;
use crate::uapi::{Direction, Mode, TripType, TEMP_INVALID};
use crate::update::{handle_trips, passive_count, trend_from_samples, Crossing};

use super::state::{views, ThermalZone};

/// What one pass produced, for the caller that owns the side effects.
#[derive(Clone, Default)]
pub struct Outcome {
    /// Reading the pass acted on, or `None` when the sensor could not be read.
    pub temperature: Option<i32>,
    /// Trips that changed state.
    pub crossings: Vec<Crossing>,
    /// Cooling devices whose aggregate request may have moved.
    pub touched: Vec<Arc<CoolingDevice>>,
    /// The platform's terminal temperature was reached.
    pub critical: bool,
    /// The platform asked to leave the running state.
    pub hot: bool,
    /// The sensor failed for long enough that the zone was disabled.
    pub broken: bool,
    /// When the zone should be read again.
    pub deadline_ns: Option<u64>,
}

/// Run one pass. `now_ns` is the monotonic clock the deadline is measured
/// against. # C: O(N_trips + N_instances)
pub fn update(zone: &ThermalZone, now_ns: u64) -> Outcome {
    let mut outcome = Outcome::default();
    if zone.mode() != Mode::Enabled { return outcome; }

    let temp = match zone.ops().get_temp() {
        Ok(temp) => temp,
        Err(_) => return on_failure(zone, now_ns, outcome),
    };
    zone.state.lock().backoff_ms = RECHECK_DELAY_MS;
    if temp <= TEMP_INVALID { return rearm(zone, now_ns, outcome); }
    outcome.temperature = Some(temp);

    let provider_trend = zone.ops().get_trend();
    let bound: Vec<Arc<CoolingDevice>> =
        zone.state.lock().instances.iter().map(|inst| Arc::clone(&inst.cdev)).collect();
    let cur_states: Vec<u64> =
        bound.iter().map(|cdev| cdev.cur_state().unwrap_or(0)).collect();

    let window = {
        let mut state = zone.state.lock();
        state.last_temperature = state.temperature;
        state.temperature = temp;
        let previous = state.last_temperature;
        let (crossings, window) = handle_trips(temp, &mut state.trips);
        outcome.crossings = crossings;
        outcome.critical = outcome.crossings.iter()
            .any(|c| c.ty == TripType::Critical && c.direction == Direction::Up);
        outcome.hot = outcome.crossings.iter()
            .any(|c| c.ty == TripType::Hot && c.direction == Direction::Up);

        let trend = provider_trend.unwrap_or_else(|| trend_from_samples(previous, temp));
        let instances = views(&state.instances, &cur_states);
        let targets = {
            let input = GovInput {
                temperature: temp,
                trend,
                trips: &state.trips,
                instances: &instances,
                crossings: &outcome.crossings,
            };
            let targets = (state.governor.govern)(&input);
            if any_change(&input, &targets) { Some(targets) } else { None }
        };
        if let Some(targets) = targets {
            for (index, target) in targets.into_iter().enumerate() {
                let Some(target) = target else { continue; };
                let Some(inst) = state.instances.get_mut(index) else { continue; };
                if inst.initialized && inst.target == target { continue; }
                inst.target = target;
                inst.initialized = true;
                outcome.touched.push(Arc::clone(&inst.cdev));
            }
        }
        window
    };

    let program = { let mut state = zone.state.lock();
        if state.window == Some(window) { None } else { state.window = Some(window); Some(window) }
    };
    if let Some(window) = program { zone.ops().set_trips(window.low, window.high); }

    rearm(zone, now_ns, outcome)
}

/// Re-arm the poll from the cadence the zone's current trip state calls for.
/// # C: O(N_trips)
fn rearm(zone: &ThermalZone, now_ns: u64, mut outcome: Outcome) -> Outcome {
    let engaged = { let state = zone.state.lock(); passive_count(&state.trips) };
    let deadline = next_delay_ms(zone.cadence(), engaged)
        .map(|delay_ms| now_ns.saturating_add(delay_ms.saturating_mul(NSEC_PER_MSEC)));
    zone.state.lock().deadline_ns = deadline;
    outcome.deadline_ns = deadline;
    outcome
}

/// Back off after a failed read, disabling a sensor that never recovers.
/// # C: O(1)
fn on_failure(zone: &ThermalZone, now_ns: u64, mut outcome: Outcome) -> Outcome {
    let not_ready = zone.ops().read_pending();
    let backoff = zone.state.lock().backoff_ms;
    match on_read_failure(backoff, not_ready) {
        Recheck::Retry { delay_ms, next_backoff_ms } => {
            let deadline = now_ns.saturating_add(delay_ms.saturating_mul(NSEC_PER_MSEC));
            let mut state = zone.state.lock();
            state.backoff_ms = next_backoff_ms;
            state.deadline_ns = Some(deadline);
            outcome.deadline_ns = Some(deadline);
        }
        Recheck::Broken => {
            let mut state = zone.state.lock();
            state.mode = Mode::Disabled;
            state.backoff_ms = RECHECK_DELAY_MS;
            state.deadline_ns = None;
            outcome.broken = true;
        }
    }
    outcome
}

/// Force every binding to be pushed again on the next pass. Used when a
/// binding is added to a zone that is already hot: with no crossing to react
/// to, a governor would otherwise leave the new device idle. # C: O(N)
pub fn desynchronise(zone: &ThermalZone) {
    let mut state = zone.state.lock();
    for inst in state.instances.iter_mut() { inst.initialized = false; }
}

/// Whether any trip of the zone is currently reached. # C: O(N_trips)
pub fn any_trip_reached(zone: &ThermalZone) -> bool {
    zone.state.lock().trips.iter().any(|desc| desc.bucket == Bucket::Reached)
}

#[cfg(test)]
#[path = "../tests/pass.rs"]
mod tests;
