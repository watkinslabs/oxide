// Building a zone's trip ladder out of the firmware objects.
//
// Order matters twice over. The objects are evaluated in a fixed order because
// firmware routinely makes one depend on another having run first. The trips
// are then appended in a fixed order — terminal first, then throttling, then
// the reacting levels — because that order is the trip index every attribute
// name and every binding is keyed by, and a ladder built in a different order
// on a later boot would rename every one of them.

use alloc::string::String;
use alloc::vec::Vec;

use thermal::{Trip, TripType};

use super::super::aml_eval;
use super::decode;

/// Object reporting the temperature past which the hardware is damaged.
pub const CRT: &str = "_CRT";
/// Object reporting the temperature at which the platform wants to leave the
/// running state.
pub const HOT: &str = "_HOT";
/// Object reporting the temperature at which throttling should begin.
pub const PSV: &str = "_PSV";
/// Object naming the devices throttled at the passive trip.
pub const PSL: &str = "_PSL";
/// Object reporting the polling cadence, tenths of a second.
pub const TZP: &str = "_TZP";
/// Object reporting the throttled sampling cadence, tenths of a second.
pub const TSP: &str = "_TSP";

/// Cadence a zone that declares none is polled at, milliseconds. A zone that
/// is never re-read is a zone whose critical trip never fires.
pub const DEFAULT_POLLING_MS: u64 = 4_000;
/// Cadence a throttled zone that declares none is polled at, milliseconds.
pub const DEFAULT_PASSIVE_MS: u64 = 1_000;

/// One zone's ladder, ready to declare.
pub struct Ladder {
    pub trips: Vec<Trip>,
    /// Namespace paths of the devices associated with each trip, in trip
    /// order.
    pub bindings: Vec<Vec<String>>,
    pub offset_mc: i64,
    pub polling_ms: u64,
    pub passive_ms: u64,
}

/// The firmware temperatures of one zone, in deci-kelvin.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Raw {
    pub critical: Option<u64>,
    pub hot: Option<u64>,
    pub passive: Option<u64>,
    /// Active levels, contiguous from zero.
    pub active: [Option<u64>; decode::MAX_ACTIVE_TRIPS],
}

/// Assemble the ladder from already-read firmware temperatures.
///
/// Terminal trips first, then the throttling trip, then the reacting levels in
/// declaration order. A level the firmware did not declare is left out rather
/// than held as a placeholder, so the indexes are contiguous.
/// # C: O(MAX_ACTIVE_TRIPS)
pub fn assemble(raw: &Raw, offset_mc: i64) -> (Vec<Trip>, Vec<usize>) {
    let mut trips = Vec::new();
    let mut active_index = Vec::new();
    let mut push = |ty: TripType, decik: Option<u64>| -> bool {
        let Some(decik) = decik else { return false; };
        let temp = decode::to_millicelsius(decik, offset_mc);
        if temp == thermal::TEMP_INVALID { return false; }
        trips.push(Trip::new(ty, temp));
        true
    };
    push(TripType::Critical, raw.critical);
    push(TripType::Hot, raw.hot);
    push(TripType::Passive, raw.passive);
    for (level, decik) in raw.active.iter().enumerate() {
        if push(TripType::Active, *decik) { active_index.push(level); }
    }
    drop(push);
    (trips, active_index)
}

/// How far the contiguous run of declared active levels reaches. Firmware
/// declares them from zero without gaps, and a gap means the rest are not
/// there rather than that one is missing. # C: O(MAX_ACTIVE_TRIPS)
pub fn active_run(active: &[Option<u64>; decode::MAX_ACTIVE_TRIPS]) -> usize {
    active.iter().position(Option::is_none).unwrap_or(active.len())
}

impl Ladder {
    /// Read one zone's whole description. # C: O(AML)
    pub fn read(scope: &str) -> Option<Ladder> {
        let critical = aml_eval::eval_integer(scope, CRT);
        let hot = aml_eval::eval_integer(scope, HOT);
        let passive = aml_eval::eval_integer(scope, PSV);
        let mut active = [None; decode::MAX_ACTIVE_TRIPS];
        for level in 0..decode::MAX_ACTIVE_TRIPS {
            let name = decode::active_trip_name(level)?;
            let name = core::str::from_utf8(&name).ok()?;
            let Some(value) = aml_eval::eval_integer(scope, name) else { break; };
            active[level] = Some(value);
        }
        let offset_mc = decode::kelvin_offset_mc(critical);
        let raw = Raw { critical, hot, passive, active };
        let (trips, active_levels) = assemble(&raw, offset_mc);

        let mut bindings = Vec::with_capacity(trips.len());
        for trip in &trips {
            bindings.push(match trip.ty {
                TripType::Passive => aml_eval::eval_reference_paths(scope, PSL),
                TripType::Active => Vec::new(),
                _ => Vec::new(),
            });
        }
        // The reacting levels come last and in declaration order, so the tail
        // of the trip list lines up with the levels that produced it.
        let first_active = trips.len() - active_levels.len();
        for (offset, level) in active_levels.iter().enumerate() {
            let Some(name) = decode::active_devices_name(*level) else { continue; };
            let Ok(name) = core::str::from_utf8(&name) else { continue; };
            bindings[first_active + offset] = aml_eval::eval_reference_paths(scope, name);
        }

        let polling_ms = aml_eval::eval_integer(scope, TZP)
            .map(decode::deciseconds_to_ms)
            .filter(|ms| *ms != 0)
            .unwrap_or(DEFAULT_POLLING_MS);
        let passive_ms = aml_eval::eval_integer(scope, TSP)
            .map(decode::deciseconds_to_ms)
            .filter(|ms| *ms != 0)
            .unwrap_or(DEFAULT_PASSIVE_MS);

        Some(Ladder { trips, bindings, offset_mc, polling_ms, passive_ms })
    }
}

#[cfg(test)]
#[path = "trips_tests.rs"]
mod tests;
