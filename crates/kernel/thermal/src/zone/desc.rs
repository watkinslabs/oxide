// What a provider hands the thermal core, and what the core asks of it.

use alloc::string::String;
use alloc::vec::Vec;
use vfs::KResult;

use crate::cdev::CoolingDevice;
use crate::monitor::Cadence;
use crate::trip::Trip;
use crate::uapi::{Trend, NO_LIMIT};

/// The provider half of a zone.
pub trait ZoneOps: Send + Sync {
    /// Current temperature, millidegrees Celsius. # C: O(provider)
    fn get_temp(&self) -> KResult<i32>;

    /// Whether a failed read means "not ready yet" rather than a fault. A
    /// sensor that is merely slow must not be backed off into disablement.
    /// # C: O(1)
    fn read_pending(&self) -> bool { false }

    /// Trend measured by the provider itself, where it can do better than
    /// comparing two samples. # C: O(provider)
    fn get_trend(&self) -> Option<Trend> { None }

    /// Program the sensor to interrupt outside `[low, high]`, where it can.
    /// # C: O(provider)
    fn set_trips(&self, _low: i32, _high: i32) {}

    /// Whether `cdev` can cool trip `trip`, and with what range. # C: O(1)
    fn should_bind(&self, _trip: usize, _cdev: &CoolingDevice) -> Option<BindSpec> { None }

    /// The platform reached its hot trip. Distinct from critical: the
    /// firmware is asking to leave the running state, not reporting damage.
    /// # C: O(provider)
    fn hot(&self) {}
}

/// The range a cooling device may be driven within for one trip, and its share
/// when several devices cool the same zone.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BindSpec {
    /// Deepest state this binding may ask for, or `NO_LIMIT` to track the
    /// device's own maximum as it changes.
    pub upper: u64,
    /// Shallowest state this binding may ask for.
    pub lower: u64,
    /// Relative share for the proportional governor; zero means unweighted.
    pub weight: u32,
}

impl Default for BindSpec {
    /// The whole range of the device, unweighted. # C: O(1)
    fn default() -> BindSpec { BindSpec { upper: NO_LIMIT, lower: 0, weight: 0 } }
}

/// One zone as a provider declares it.
pub struct ZoneDesc {
    /// Provider-declared kind, as `type` reads it back.
    pub ty: String,
    /// Trips in the order they become `trip_point_<n>_*`.
    pub trips: Vec<Trip>,
    /// Ordinary and throttled polling cadences.
    pub cadence: Cadence,
    /// Governor the provider asks for, by name. An unknown name falls back to
    /// the default rather than leaving the zone ungoverned.
    pub governor: Option<String>,
}

impl ZoneDesc {
    /// A zone with the default governor. # C: O(1)
    pub fn new(ty: &str, trips: Vec<Trip>, cadence: Cadence) -> ZoneDesc {
        ZoneDesc { ty: String::from(ty), trips, cadence, governor: None }
    }

    /// Name the governor this zone should run. # C: O(1)
    pub fn with_governor(mut self, name: &str) -> ZoneDesc {
        self.governor = Some(String::from(name));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::TripType;

    #[test]
    fn the_default_bind_takes_the_whole_device_range_unweighted() {
        let spec = BindSpec::default();
        assert_eq!(spec.lower, 0);
        assert_eq!(spec.upper, NO_LIMIT);
        assert_eq!(spec.weight, 0);
    }

    #[test]
    fn a_declared_governor_name_is_carried_on_the_declaration() {
        let desc = ZoneDesc::new("acpitz", alloc::vec![Trip::new(TripType::Critical, 100_000)],
                                 Cadence::polled(4_000));
        assert!(desc.governor.is_none());
        let desc = desc.with_governor("bang_bang");
        assert_eq!(desc.governor.as_deref(), Some("bang_bang"));
        assert_eq!(desc.ty, "acpitz");
    }
}
