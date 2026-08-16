// One trip point and the bucket that records where the zone's temperature
// currently sits relative to it. The bucket, not a re-comparison against the
// trip temperature, is what makes hysteresis work: a trip that has been
// reached stays reached until the temperature falls a whole hysteresis band
// below it, and the threshold field carries whichever of the two edges is the
// one still to be crossed.

use crate::uapi::{TripType, TEMP_INVALID, TRIP_FLAG_RW_HYST, TRIP_FLAG_RW_TEMP};

/// One declared trip point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Trip {
    /// Trip temperature, millidegrees Celsius. `TEMP_INVALID` disables it.
    pub temperature: i32,
    /// How far below `temperature` the zone must fall to leave the trip,
    /// millidegrees Celsius. Never negative.
    pub hysteresis: i32,
    pub ty: TripType,
    pub flags: u8,
}

impl Trip {
    /// A read-only trip at `temperature` with no hysteresis band. # C: O(1)
    pub fn new(ty: TripType, temperature: i32) -> Trip {
        Trip { temperature, hysteresis: 0, ty, flags: 0 }
    }

    /// A trip with a hysteresis band. # C: O(1)
    pub fn with_hysteresis(ty: TripType, temperature: i32, hysteresis: i32) -> Trip {
        Trip { temperature, hysteresis, ty, flags: 0 }
    }

    /// Whether userspace may write this trip's temperature. # C: O(1)
    pub fn temp_writable(&self) -> bool { self.flags & TRIP_FLAG_RW_TEMP != 0 }

    /// Whether userspace may write this trip's hysteresis. # C: O(1)
    pub fn hyst_writable(&self) -> bool { self.flags & TRIP_FLAG_RW_HYST != 0 }

    /// Whether the trip participates in crossing detection at all. # C: O(1)
    pub fn valid(&self) -> bool { self.temperature != TEMP_INVALID }
}

/// Where the zone temperature sits relative to one trip.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Bucket {
    /// The trip declares no temperature, so it can never be crossed.
    Invalid,
    /// Not reached: the next crossing is upward, at the trip temperature.
    High,
    /// Reached: the next crossing is downward, a hysteresis band below.
    Reached,
}

/// A trip plus its crossing state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TripDesc {
    pub trip: Trip,
    pub bucket: Bucket,
}

impl TripDesc {
    /// A freshly declared trip, before the first temperature reading.
    /// # C: O(1)
    pub fn new(trip: Trip) -> TripDesc {
        let bucket = if trip.valid() { Bucket::High } else { Bucket::Invalid };
        TripDesc { trip, bucket }
    }

    /// The temperature at which this trip's next crossing happens: the trip
    /// temperature while it is unreached, and the bottom of the hysteresis
    /// band once it has been. `None` for a trip that declares none. # C: O(1)
    pub fn threshold(&self) -> Option<i32> {
        match self.bucket {
            Bucket::Invalid => None,
            Bucket::High => Some(self.trip.temperature),
            Bucket::Reached => Some(self.trip.temperature - self.trip.hysteresis),
        }
    }

    /// Re-derive the bucket after the trip's own temperature changed. A trip
    /// that goes invalid while reached must report the downward crossing, or a
    /// cooling device stays engaged for a trip that no longer exists.
    /// # C: O(1)
    pub fn revalidate(&mut self) -> bool {
        if self.trip.valid() { return false; }
        let was_reached = self.bucket == Bucket::Reached;
        self.bucket = Bucket::Invalid;
        was_reached
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreached_trip_reports_its_own_temperature_as_the_next_edge() {
        let desc = TripDesc::new(Trip::with_hysteresis(TripType::Active, 60_000, 5_000));
        assert_eq!(desc.bucket, Bucket::High);
        assert_eq!(desc.threshold(), Some(60_000));
    }

    #[test]
    fn a_reached_trip_reports_the_bottom_of_the_hysteresis_band() {
        let mut desc = TripDesc::new(Trip::with_hysteresis(TripType::Active, 60_000, 5_000));
        desc.bucket = Bucket::Reached;
        assert_eq!(desc.threshold(), Some(55_000),
                   "the downward edge is a whole band below the trip");
    }

    #[test]
    fn a_trip_with_no_declared_temperature_has_no_edge() {
        let desc = TripDesc::new(Trip::new(TripType::Passive, TEMP_INVALID));
        assert_eq!(desc.bucket, Bucket::Invalid);
        assert_eq!(desc.threshold(), None);
    }

    #[test]
    fn a_reached_trip_going_invalid_reports_a_downward_crossing() {
        let mut desc = TripDesc::new(Trip::new(TripType::Active, 60_000));
        desc.bucket = Bucket::Reached;
        desc.trip.temperature = TEMP_INVALID;
        assert!(desc.revalidate(), "a cooling device bound here must be released");
        assert_eq!(desc.bucket, Bucket::Invalid);

        let mut unreached = TripDesc::new(Trip::new(TripType::Active, 60_000));
        unreached.trip.temperature = TEMP_INVALID;
        assert!(!unreached.revalidate());
    }

    #[test]
    fn writability_comes_from_the_declared_flags() {
        let mut trip = Trip::new(TripType::Active, 60_000);
        assert!(!trip.temp_writable() && !trip.hyst_writable());
        trip.flags = TRIP_FLAG_RW_TEMP;
        assert!(trip.temp_writable() && !trip.hyst_writable());
        trip.flags = TRIP_FLAG_RW_TEMP | TRIP_FLAG_RW_HYST;
        assert!(trip.temp_writable() && trip.hyst_writable());
    }
}
