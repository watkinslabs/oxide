// Trip crossing detection. Pure over the trip array and one temperature, so
// the hysteresis rule is checkable without a sensor: this is the decision that
// turns a reading into "the fan comes on" or "the machine goes down", and a
// wrong comparison here is a fan that chatters or a trip that never fires.

use alloc::vec::Vec;

use crate::trip::{Bucket, TripDesc};
use crate::uapi::{Direction, Trend, TripType};

/// One trip changing state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Crossing {
    /// Index into the zone's trip array.
    pub index: usize,
    pub ty: TripType,
    pub direction: Direction,
}

/// The temperature window outside which the next reading is interesting. A
/// sensor that can raise an interrupt is programmed with it, so a zone whose
/// temperature sits between two trips needs no polling at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Window { pub low: i32, pub high: i32 }

/// Window meaning "no bound"; the extremes rather than the type limits, so a
/// provider that adds one to `low` cannot wrap.
pub const WINDOW_UNBOUNDED: Window = Window { low: -i32::MAX, high: i32::MAX };

/// Reclassify every trip against `temp`, reporting the crossings and the new
/// interrupt window.
///
/// Upward crossing is inclusive at the trip temperature; downward crossing
/// needs the temperature strictly below the whole hysteresis band. Reported in
/// index order, downward crossings first: a trip released at a lower
/// temperature must not be re-engaged by a trip reached in the same pass.
/// # C: O(N_trips)
pub fn handle_trips(temp: i32, trips: &mut [TripDesc]) -> (Vec<Crossing>, Window) {
    let mut crossings = Vec::new();
    for (index, desc) in trips.iter_mut().enumerate() {
        if desc.bucket != Bucket::Reached { continue; }
        let Some(threshold) = desc.threshold() else { continue; };
        if threshold <= temp { continue; }
        desc.bucket = Bucket::High;
        crossings.push(Crossing { index, ty: desc.trip.ty, direction: Direction::Down });
    }
    for (index, desc) in trips.iter_mut().enumerate() {
        if desc.bucket != Bucket::High { continue; }
        let Some(threshold) = desc.threshold() else { continue; };
        if threshold > temp { continue; }
        desc.bucket = Bucket::Reached;
        crossings.push(Crossing { index, ty: desc.trip.ty, direction: Direction::Up });
    }
    (crossings, window(trips))
}

/// The window between the highest edge already below the temperature and the
/// lowest edge still above it. # C: O(N_trips)
pub fn window(trips: &[TripDesc]) -> Window {
    let mut win = WINDOW_UNBOUNDED;
    for desc in trips {
        let Some(threshold) = desc.threshold() else { continue; };
        match desc.bucket {
            Bucket::Reached => if threshold - 1 > win.low { win.low = threshold - 1; },
            Bucket::High => if threshold < win.high { win.high = threshold; },
            Bucket::Invalid => {}
        }
    }
    win
}

/// How many passive trips are currently engaged. The zone polls at its passive
/// cadence while any of them is. # C: O(N_trips)
pub fn passive_count(trips: &[TripDesc]) -> usize {
    trips.iter()
        .filter(|desc| desc.bucket == Bucket::Reached && desc.trip.ty == TripType::Passive)
        .count()
}

/// Trend between the last two readings. A provider that measures the trend
/// itself supplies it instead; this is the fallback every zone gets.
/// # C: O(1)
pub fn trend_from_samples(previous: i32, current: i32) -> Trend {
    if current > previous { Trend::Raising }
    else if current < previous { Trend::Dropping }
    else { Trend::Stable }
}

#[cfg(test)]
#[path = "tests/update.rs"]
mod tests;
