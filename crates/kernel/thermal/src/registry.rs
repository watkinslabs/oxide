// The thermal class: the registered zones and cooling devices, the binding
// that happens when either appears, and the aggregation that decides what a
// device shared between zones is actually driven to.
//
// One list of each. A provider registers here and nowhere else; sysfs reads
// this and nothing else. A second list would be a class tree that disagrees
// with itself about which devices exist.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::cdev::{CoolingDevice, CoolingOps};
use crate::governor::input::aggregate;
use crate::monitor::Cadence;
use crate::trip::{Trip, TripDesc};
use crate::uapi::Direction;
use crate::zone::bind;
use crate::zone::pass::{self, Outcome};
use crate::zone::{ThermalZone, ZoneDesc, ZoneOps};

/// Called with a class device name whenever something a reader can observe
/// changed. sysfs installs one to turn it into a `change` uevent.
pub type ChangeHook = fn(&str);

/// Called when a zone crosses a governed trip under a governor that publishes
/// crossings instead of cooling: zone name, temperature, trip index,
/// direction.
pub type CrossingHook = fn(&str, i32, usize, Direction);

/// Called when a zone reaches the temperature past which the hardware is
/// damaged. The kernel installs the orderly shutdown; a host build installs
/// nothing, so the decision stays testable.
pub type CriticalHook = fn(&str, i32);

static ZONES: Spinlock<Vec<Arc<ThermalZone>>, Devices> = Spinlock::new(Vec::new());
static CDEVS: Spinlock<Vec<Arc<CoolingDevice>>, Devices> = Spinlock::new(Vec::new());
static NEXT_ZONE: AtomicU32 = AtomicU32::new(0);
static NEXT_CDEV: AtomicU32 = AtomicU32::new(0);
static CHANGE_HOOK: Spinlock<Option<ChangeHook>, Devices> = Spinlock::new(None);
static CROSSING_HOOK: Spinlock<Option<CrossingHook>, Devices> = Spinlock::new(None);
static CRITICAL_HOOK: Spinlock<Option<CriticalHook>, Devices> = Spinlock::new(None);

/// Install the class change callback. # C: O(1)
pub fn set_change_hook(hook: ChangeHook) { *CHANGE_HOOK.lock() = Some(hook); }
/// Install the crossing-publication callback. # C: O(1)
pub fn set_crossing_hook(hook: CrossingHook) { *CROSSING_HOOK.lock() = Some(hook); }
/// Install the terminal-temperature action. # C: O(1)
pub fn set_critical_hook(hook: CriticalHook) { *CRITICAL_HOOK.lock() = Some(hook); }

/// Every registered zone, in registration order. # C: O(N_zones)
pub fn zones() -> Vec<Arc<ThermalZone>> { ZONES.lock().iter().map(Arc::clone).collect() }
/// Every registered cooling device, in registration order. # C: O(N_cdevs)
pub fn cooling_devices() -> Vec<Arc<CoolingDevice>> {
    CDEVS.lock().iter().map(Arc::clone).collect()
}

/// Class device names, zones then cooling devices. # C: O(N)
pub fn device_names() -> Vec<String> {
    let mut names: Vec<String> = zones().iter().map(|zone| zone.name()).collect();
    names.extend(cooling_devices().iter().map(|cdev| cdev.name()));
    names
}

/// Resolve a zone by its class device name. # C: O(N_zones)
pub fn zone_by_name(name: &str) -> Option<Arc<ThermalZone>> {
    zones().into_iter().find(|zone| zone.name() == name)
}

/// Resolve a cooling device by its class device name. # C: O(N_cdevs)
pub fn cdev_by_name(name: &str) -> Option<Arc<CoolingDevice>> {
    cooling_devices().into_iter().find(|cdev| cdev.name() == name)
}

/// Register a zone and bind it to every cooling device that can cool it.
/// # C: O(N_cdevs * N_trips)
pub fn register_zone(desc: ZoneDesc, ops: Arc<dyn ZoneOps>) -> KResult<Arc<ThermalZone>> {
    if desc.ty.is_empty() || desc.ty.len() > crate::limits::NAME_LEN {
        return Err(VfsError::Einval);
    }
    let id = NEXT_ZONE.fetch_add(1, Ordering::Relaxed);
    let zone = Arc::new(ThermalZone::new(id, desc, ops));
    ZONES.lock().push(Arc::clone(&zone));
    for cdev in cooling_devices() { bind_pair(&zone, &cdev); }
    notify(&zone.name());
    Ok(zone)
}

/// Unregister a zone and remove every cooling binding to it before dropping
/// the class's reference. # C: O(N_cdevs)
pub fn unregister_zone(zone: &Arc<ThermalZone>) -> bool {
    for (_, _, cdev) in zone.bindings() { bind::unbind(zone, &cdev); }
    let mut zones = ZONES.lock();
    let Some(index) = zones.iter().position(|entry| Arc::ptr_eq(entry, zone)) else {
        return false;
    };
    zones.remove(index);
    true
}

/// Register a cooling device and bind it into every zone that can use it.
/// # C: O(N_zones * N_trips)
pub fn register_cdev(ty: &str, ops: Arc<dyn CoolingOps>, now_ns: u64)
    -> KResult<Arc<CoolingDevice>>
{
    register_cdev_inner(ty, None, ops, now_ns)
}

/// Register a cooling device corresponding to an exact firmware namespace
/// object. The class-visible type remains a provider kind; the object path is
/// matching identity and is not exposed as that type. # C: O(N_zones * N_trips)
pub fn register_cdev_for_path(ty: &str, path: &str, ops: Arc<dyn CoolingOps>, now_ns: u64)
    -> KResult<Arc<CoolingDevice>>
{
    if path.is_empty() { return Err(VfsError::Einval); }
    register_cdev_inner(ty, Some(path), ops, now_ns)
}

/// Build and publish one cooling device after its type and optional identity
/// passed the public API's validation. # C: O(N_zones * N_trips)
fn register_cdev_inner(ty: &str, path: Option<&str>, ops: Arc<dyn CoolingOps>, now_ns: u64)
    -> KResult<Arc<CoolingDevice>>
{
    if ty.is_empty() || ty.len() > crate::limits::NAME_LEN { return Err(VfsError::Einval); }
    let max_state = ops.max_state()?;
    let id = NEXT_CDEV.fetch_add(1, Ordering::Relaxed);
    let cdev = Arc::new(CoolingDevice::with_binding(id, ty, path, ops, max_state, now_ns));
    CDEVS.lock().push(Arc::clone(&cdev));
    for zone in zones() { bind_pair(&zone, &cdev); }
    notify(&cdev.name());
    Ok(cdev)
}

/// Unregister a cooling device, dropping every binding to it first so no zone
/// keeps asking a device that is gone for a state. # C: O(N_zones)
pub fn unregister_cdev(cdev: &Arc<CoolingDevice>) -> bool {
    for zone in zones() { bind::unbind(&zone, cdev); }
    let mut cdevs = CDEVS.lock();
    let Some(index) = cdevs.iter().position(|entry| Arc::ptr_eq(entry, cdev)) else {
        return false;
    };
    cdevs.remove(index);
    true
}

/// Offer `cdev` to every trip of `zone`, letting the zone's provider decide.
/// # C: O(N_trips)
fn bind_pair(zone: &Arc<ThermalZone>, cdev: &Arc<CoolingDevice>) {
    let mut bound = false;
    for trip in 0..zone.trip_count() {
        let Some(spec) = zone.ops().should_bind(trip, cdev) else { continue; };
        if bind::bind(zone, trip, cdev, spec).is_ok() { bound = true; }
    }
    // A device bound to a zone that is already hot has no crossing to react
    // to; the next pass must push it rather than leave it idle.
    if bound { pass::desynchronise(zone); }
}

fn detach_cdevs(state: &mut crate::zone::state::ZoneState) -> Vec<Arc<CoolingDevice>> {
    let mut cdevs: Vec<Arc<CoolingDevice>> = Vec::new();
    for instance in &state.instances {
        if !cdevs.iter().any(|old| Arc::ptr_eq(old, &instance.cdev)) {
            cdevs.push(Arc::clone(&instance.cdev));
        }
    }
    state.instances.clear();
    state.next_instance = 0;
    cdevs
}

/// Replace a firmware zone's trip ladder and cadence, then rebuild every
/// cooling-device binding against the provider's current description. Old
/// requests are removed before the devices are offered to the new ladder.
/// # C: O(N_instances + N_cdevs * N_trips)
pub fn reconfigure_zone(zone: &Arc<ThermalZone>, trips: Vec<Trip>, cadence: Cadence,
                        now_ns: u64) {
    let old_cdevs = {
        let mut state = zone.state.lock();
        let cdevs = detach_cdevs(&mut state);
        state.trips = trips.into_iter().map(TripDesc::new).collect();
        state.cadence = cadence;
        state.window = None;
        state.deadline_ns = None;
        cdevs
    };
    for cdev in &old_cdevs { let _ = apply_cdev(cdev, now_ns); }
    for cdev in cooling_devices() { bind_pair(zone, &cdev); }
    notify(&zone.name());
}

/// Rebuild only a firmware zone's cooling-device bindings. Trip temperatures,
/// cadence, and current sensor window remain owned by the existing ladder.
/// # C: O(N_instances + N_cdevs * N_trips)
pub fn rebind_zone(zone: &Arc<ThermalZone>, now_ns: u64) {
    let old_cdevs = detach_cdevs(&mut zone.state.lock());
    for cdev in &old_cdevs { let _ = apply_cdev(cdev, now_ns); }
    for cdev in cooling_devices() { bind_pair(zone, &cdev); }
    notify(&zone.name());
}

/// Drive `cdev` to the deepest state any zone currently asks of it.
/// # C: O(N_zones * N_instances)
pub fn apply_cdev(cdev: &Arc<CoolingDevice>, now_ns: u64) -> KResult<()> {
    let requests: Vec<u64> = zones().iter().flat_map(|zone| zone.requests_for(cdev)).collect();
    let state = aggregate(requests.into_iter());
    if cdev.cur_state() == Ok(state) { return Ok(()); }
    cdev.set_cur_state(state, now_ns)?;
    notify(&cdev.name());
    Ok(())
}

/// Consume one zone pass: run the terminal actions, publish what the governor
/// asked to be published, and drive the devices it moved. # C: O(N_touched)
pub fn consume(zone: &Arc<ThermalZone>, outcome: &Outcome, now_ns: u64) {
    if outcome.hot { zone.ops().hot(); }
    if outcome.critical {
        let hook = *CRITICAL_HOOK.lock();
        let temp = outcome.temperature.unwrap_or(crate::uapi::TEMP_INVALID);
        if let Some(hook) = hook { hook(&zone.name(), temp); }
    }
    if publishes(zone) {
        let hook = *CROSSING_HOOK.lock();
        if let Some(hook) = hook {
            let temp = outcome.temperature.unwrap_or(crate::uapi::TEMP_INVALID);
            for crossing in &outcome.crossings {
                if !crossing.ty.governed() { continue; }
                hook(&zone.name(), temp, crossing.index, crossing.direction);
            }
        }
    }
    let mut applied: Vec<Arc<CoolingDevice>> = Vec::new();
    for cdev in &outcome.touched {
        if applied.iter().any(|seen| Arc::ptr_eq(seen, cdev)) { continue; }
        applied.push(Arc::clone(cdev));
        let _ = apply_cdev(cdev, now_ns);
    }
    if outcome.broken || !outcome.crossings.is_empty() { notify(&zone.name()); }
}

/// Whether the zone's governor reports crossings to userspace. # C: O(1)
fn publishes(zone: &Arc<ThermalZone>) -> bool {
    crate::governor::by_name(zone.policy()).is_some_and(|gov| gov.publishes_crossings)
}

/// Update one zone and consume the result. # C: O(N_trips + N_instances)
pub fn update_zone(zone: &Arc<ThermalZone>, now_ns: u64) -> Outcome {
    let outcome = pass::update(zone, now_ns);
    consume(zone, &outcome, now_ns);
    outcome
}

/// Update every zone whose scheduled read is due, reporting how many ran.
/// # C: O(N_due * (N_trips + N_instances))
pub fn tick(now_ns: u64) -> usize {
    let mut ran = 0;
    for zone in zones() {
        if zone.deadline_ns().is_none_or(|deadline| deadline > now_ns) { continue; }
        update_zone(&zone, now_ns);
        ran += 1;
    }
    ran
}

/// Earliest scheduled read across every zone. # C: O(N_zones)
pub fn next_deadline_ns() -> Option<u64> {
    zones().iter().filter_map(|zone| zone.deadline_ns()).min()
}

/// Read every zone once, whatever its deadline. The first pass after
/// registration has no deadline yet, and a provider notification asks for a
/// read now rather than at the cadence. # C: O(N_zones)
pub fn update_all(now_ns: u64) {
    for zone in zones() { update_zone(&zone, now_ns); }
}

/// Publish a class change for one device. # C: O(1)
pub fn notify(name: &str) {
    let hook = *CHANGE_HOOK.lock();
    if let Some(hook) = hook { hook(name); }
}

/// Empty the class between tests. # C: O(N)
#[cfg(test)]
pub fn clear_for_tests() {
    ZONES.lock().clear();
    CDEVS.lock().clear();
    *CHANGE_HOOK.lock() = None;
    *CROSSING_HOOK.lock() = None;
    *CRITICAL_HOOK.lock() = None;
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
