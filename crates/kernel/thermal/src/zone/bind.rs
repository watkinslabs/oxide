// Attaching a cooling device to a trip of a zone, and keeping the bound range
// honest when the device's own range changes.

use alloc::sync::Arc;
use vfs::{KResult, VfsError};

use crate::cdev::CoolingDevice;
use crate::uapi::{NO_LIMIT, NO_TARGET};

use super::desc::BindSpec;
use super::state::{Instance, ThermalZone};

/// Bind `cdev` to trip `trip` of `zone`.
///
/// `NO_LIMIT` as the upper bound means "the whole device", and the binding
/// then follows the device if it later reports a deeper range — a fan that
/// gains a speed must not stay capped at the range it had at bind time.
/// A range the device cannot satisfy is refused rather than silently clamped,
/// because a provider asking for a state that does not exist has a bug the
/// clamp would hide. # C: O(N_instances)
pub fn bind(zone: &ThermalZone, trip: usize, cdev: &Arc<CoolingDevice>, spec: BindSpec)
    -> KResult<u32>
{
    let max = cdev.max_state();
    let upper_no_limit = spec.upper == NO_LIMIT;
    let upper = if upper_no_limit { max } else { spec.upper };
    let lower = spec.lower;
    if lower > upper || upper > max { return Err(VfsError::Einval); }

    let mut state = zone.state.lock();
    if trip >= state.trips.len() { return Err(VfsError::Einval); }
    if state.instances.iter().any(|inst| inst.trip == trip && Arc::ptr_eq(&inst.cdev, cdev)) {
        return Err(VfsError::Eexist);
    }
    let id = state.next_instance;
    state.next_instance += 1;
    state.instances.push(Instance {
        id,
        trip,
        cdev: Arc::clone(cdev),
        upper,
        lower,
        weight: spec.weight,
        upper_no_limit,
        target: NO_TARGET,
        initialized: false,
    });
    Ok(id)
}

/// Drop every binding of `cdev` from `zone`, reporting how many went.
/// # C: O(N_instances)
pub fn unbind(zone: &ThermalZone, cdev: &Arc<CoolingDevice>) -> usize {
    let mut state = zone.state.lock();
    let before = state.instances.len();
    state.instances.retain(|inst| !Arc::ptr_eq(&inst.cdev, cdev));
    before - state.instances.len()
}

/// Reconcile every binding of `cdev` after its range changed.
///
/// A binding that took the whole device follows it upward. A binding with an
/// explicit ceiling keeps it, because the provider chose that number. Either
/// way a range that no longer fits is pulled down, target included: a request
/// for a state the device no longer has would be refused on every apply, and
/// the zone would look as though it had stopped cooling. # C: O(N_instances)
pub fn refresh_range(zone: &ThermalZone, cdev: &Arc<CoolingDevice>) {
    let max = cdev.max_state();
    let mut state = zone.state.lock();
    for inst in state.instances.iter_mut() {
        if !Arc::ptr_eq(&inst.cdev, cdev) { continue; }
        if inst.upper < max && inst.upper_no_limit { inst.upper = max; }
        if inst.upper > max {
            inst.upper = max;
            if inst.lower > inst.upper { inst.lower = inst.upper; }
            if inst.target != NO_TARGET && inst.target > inst.upper { inst.target = inst.upper; }
        }
    }
}

#[cfg(test)]
#[path = "../tests/bind.rs"]
mod tests;
