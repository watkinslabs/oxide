//! ACPI thermal zone provider.
//!
//! Module manifest:
//! - `decode`: temperature and cadence conversion from the firmware units.
//! - `trips`: building the trip ladder from the firmware objects.
//! - this file: namespace scan, the zone provider, and class registration.

pub mod decode;
pub mod trips;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use thermal::{BindSpec, CoolingDevice, Cadence, ThermalZone, Trend, ZoneDesc, ZoneOps,
              TEMP_INVALID};
use vfs::{KResult, VfsError};

use super::aml_eval;
use trips::Ladder;

/// Object that reports the zone's current temperature.
const TMP: &str = "_TMP";
/// Object that selects the platform's cooling preference.
const SCP: &str = "_SCP";
/// Cooling preference: react before throttling, which is what a machine with
/// a fan wants; the alternative trades noise for speed.
const SCP_ACTIVE: u64 = 0;

/// One firmware-described thermal zone.
pub struct AcpiZone {
    scope: String,
    /// Kelvin offset this platform's firmware uses, millidegrees.
    offset_mc: i64,
    /// Namespace paths of the devices associated with each trip, in trip
    /// order. Empty where the firmware named none.
    bindings: Vec<Vec<String>>,
    published: Spinlock<Option<Arc<ThermalZone>>, Devices>,
}

impl ZoneOps for AcpiZone {
    fn get_temp(&self) -> KResult<i32> {
        let raw = aml_eval::eval_integer(&self.scope, TMP).ok_or(VfsError::Eio)?;
        let temp = decode::to_millicelsius(raw, self.offset_mc);
        if temp == TEMP_INVALID { return Err(VfsError::Eio); }
        Ok(temp)
    }

    /// Firmware reports a temperature, never a direction; the class derives
    /// the trend from consecutive readings. # C: O(1)
    fn get_trend(&self) -> Option<Trend> { None }

    /// Whether `cdev` is one of the devices the firmware associated with
    /// `trip`. Matched by namespace identity instead of the class-visible
    /// type: binding by position would attach a fan to whichever trip happened
    /// to be listed alongside it.
    /// # C: O(N_bound)
    fn should_bind(&self, trip: usize, cdev: &CoolingDevice) -> Option<BindSpec> {
        let names = self.bindings.get(trip)?;
        if matches_path(names, cdev) { Some(BindSpec::default()) } else { None }
    }
}

/// Whether this cooling device is the exact ACPI object firmware named.
/// # C: O(N_bound)
fn matches_path(names: &[String], cdev: &CoolingDevice) -> bool {
    let Some(path) = cdev.binding_path() else { return false; };
    names.iter().any(|name| name == path)
}

impl AcpiZone {
    /// Ask the platform to prefer reacting over throttling. Best effort: a
    /// firmware that declares no preference object has one policy.
    /// # C: O(AML)
    fn set_cooling_mode(&self) {
        let _ = aml_eval::eval_with_integer(&self.scope, SCP, SCP_ACTIVE);
    }

    /// Re-read the zone now, because a firmware notification means the
    /// temperature or the trip ladder moved and the polling cadence is too
    /// slow to be the answer. # C: O(AML)
    pub fn notified(&self, now_ns: u64) {
        let published = self.published.lock().clone();
        if let Some(zone) = published { thermal::update_zone(&zone, now_ns); }
    }
}

/// Scan the firmware namespace and publish every thermal zone it describes.
/// Returns how many were registered. # C: O(namespace + AML)
pub fn init() -> usize {
    let mut registered = 0;
    for scope in aml_eval::thermal_zones() {
        if register_one(&scope).is_some() { registered += 1; }
    }
    registered
}

/// Publish one zone. A zone whose ladder has no usable trip is not published:
/// a thermal zone that can never act is a temperature readout, and publishing
/// it as a zone tells a daemon the machine is protected when it is not.
/// # C: O(AML)
fn register_one(scope: &str) -> Option<Arc<ThermalZone>> {
    // Every temperature object is evaluated once before the ladder is built.
    // Firmware routinely makes one of them depend on another having run, and
    // the order below is the one that satisfies those dependencies.
    let ladder = Ladder::read(scope)?;
    if ladder.trips.is_empty() { return None; }

    let zone = Arc::new(AcpiZone {
        scope: String::from(scope),
        offset_mc: ladder.offset_mc,
        bindings: ladder.bindings,
        published: Spinlock::new(None),
    });
    zone.set_cooling_mode();

    let desc = ZoneDesc::new(&zone_type(scope), ladder.trips,
                             Cadence { polling_ms: ladder.polling_ms,
                                       passive_ms: ladder.passive_ms });
    let published = thermal::register_zone(desc, zone.clone() as Arc<dyn ZoneOps>).ok()?;
    *zone.published.lock() = Some(Arc::clone(&published));
    Some(published)
}

/// The zone's kind, as `type` reads it back: the last component of its
/// firmware object name, which is what a platform names its zones by.
/// # C: O(len)
fn zone_type(scope: &str) -> String {
    let leaf = scope.rsplit('.').next().unwrap_or(scope);
    let leaf = leaf.trim_start_matches('\\').trim_start_matches('_');
    let leaf = if leaf.is_empty() { "acpitz" } else { leaf };
    let mut name = String::from(leaf);
    name.make_ascii_lowercase();
    name
}

#[cfg(test)]
#[path = "thermal/zone_tests.rs"]
mod tests;
