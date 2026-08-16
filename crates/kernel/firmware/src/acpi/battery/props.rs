//! Mapping from a decoded battery reading to power-supply properties.
//!
//! Pure: it takes an `Info`/`State` pair and answers property reads, so the
//! unit scaling, the status ladder and the percentage arithmetic are all
//! checkable without firmware.

use alloc::string::String;
use alloc::vec::Vec;
use power_supply::{CapacityLevel, Property, PropVal, Status, Technology};
use vfs::{KResult, VfsError};

use super::decode::{capacity_valid, full_capacity, full_cap_broken, to_micro, Info, State,
                    STATE_CHARGE_LIMITING, STATE_CHARGING, STATE_CRITICAL, STATE_DISCHARGING,
                    VALUE_UNKNOWN};

/// Percentage denominator scale.
const PERCENT: u64 = 100;

/// Battery chemistry from the firmware type string. Firmware capitalises this
/// field inconsistently, so the comparison is case-insensitive; `Li-ion` is a
/// prefix match because tables append revision text to it. # C: O(n)
pub fn technology(battery_type: &str) -> Technology {
    let lowered = battery_type.to_ascii_lowercase();
    if lowered == "nicd" { return Technology::NiCd; }
    if lowered == "nimh" { return Technology::NiMh; }
    if lowered == "lion" { return Technology::LiIon; }
    if lowered.starts_with("li-ion") { return Technology::LiIon; }
    if lowered == "lip" { return Technology::LiPoly; }
    Technology::Unknown
}

/// A battery is charged when nothing is happening to it and its charge has
/// reached a full-charge reference. # C: O(1)
pub fn is_charged(info: &Info, state: &State) -> bool {
    if state.state != 0 { return false; }
    if state.capacity_now == VALUE_UNKNOWN || state.capacity_now == 0 { return false; }
    if info.full_charge_capacity == state.capacity_now { return true; }
    info.design_capacity <= state.capacity_now
}

/// Charge status. `system_supplied` reports whether some other supply is
/// feeding the machine: a battery that claims to be discharging at zero rate
/// while the machine is on mains is not discharging. # C: O(1)
pub fn status(info: &Info, state: &State, system_supplied: bool) -> Status {
    if state.state & STATE_DISCHARGING != 0 {
        if system_supplied && state.rate_now == 0 { return Status::NotCharging; }
        return Status::Discharging;
    }
    if state.state & STATE_CHARGING != 0 {
        if state.rate_now != VALUE_UNKNOWN && state.rate_now == 0 { return Status::NotCharging; }
        return Status::Charging;
    }
    if state.state & STATE_CHARGE_LIMITING != 0 { return Status::NotCharging; }
    if is_charged(info, state) { return Status::Full; }
    Status::NotCharging
}

/// Charge percentage, rounded to nearest. # C: O(1)
pub fn capacity_percent(info: &Info, state: &State) -> Option<i32> {
    if state.capacity_now == VALUE_UNKNOWN { return None; }
    let full = u64::from(full_capacity(info)?);
    let scaled = u64::from(state.capacity_now) * PERCENT;
    Some(((scaled + full / 2) / full) as i32)
}

/// Coarse charge level. The firmware's own critical flag outranks the alarm
/// threshold, because a battery that says it is about to die is not merely
/// low. # C: O(1)
pub fn capacity_level(info: &Info, state: &State, alarm: Option<u32>) -> CapacityLevel {
    if state.state & STATE_CRITICAL != 0 { return CapacityLevel::Critical; }
    if let Some(alarm) = alarm {
        if state.capacity_now != VALUE_UNKNOWN && state.capacity_now <= alarm {
            return CapacityLevel::Low;
        }
    }
    if is_charged(info, state) { return CapacityLevel::Full; }
    CapacityLevel::Normal
}

/// Properties this battery can answer. Which capacity family is published
/// depends on the unit firmware reports in: a battery measured in mAh
/// publishes `charge_*`, one measured in mWh publishes `energy_*`, and one
/// with no usable full-charge reference publishes neither rather than
/// publishing a percentage it cannot compute. # C: O(1)
pub fn properties(info: &Info) -> Vec<Property> {
    let mut props = alloc::vec![
        Property::Status, Property::Present, Property::Technology, Property::CycleCount,
        Property::VoltageMinDesign, Property::VoltageNow,
    ];
    props.push(if info.power_unit_ma { Property::CurrentNow } else { Property::PowerNow });
    if !full_cap_broken(info) {
        if info.power_unit_ma {
            props.push(Property::ChargeFullDesign);
            props.push(Property::ChargeFull);
        } else {
            props.push(Property::EnergyFullDesign);
            props.push(Property::EnergyFull);
        }
    }
    props.push(if info.power_unit_ma { Property::ChargeNow } else { Property::EnergyNow });
    if !full_cap_broken(info) {
        props.push(Property::Capacity);
        props.push(Property::CapacityLevel);
    }
    props.push(Property::ModelName);
    props.push(Property::Manufacturer);
    props.push(Property::SerialNumber);
    props
}

/// Everything a property read needs about the battery right now.
pub struct Reading<'a> {
    pub present: bool,
    pub info: &'a Info,
    pub state: &'a State,
    pub alarm: Option<u32>,
    pub system_supplied: bool,
}

/// Answer one property. An absent battery answers only `present`: every other
/// value would be a stale reading presented as current. A field firmware did
/// not report is `ENODEV`, distinct from a property the battery does not have
/// at all. # C: O(1)
pub fn get(reading: &Reading, prop: Property) -> KResult<PropVal> {
    if !reading.present && prop != Property::Present { return Err(VfsError::Enodev); }
    let (info, state) = (reading.info, reading.state);
    match prop {
        Property::Status => Ok(PropVal::Int(
            status(info, state, reading.system_supplied) as i32)),
        Property::Present => Ok(PropVal::Int(i32::from(reading.present))),
        Property::Technology => Ok(PropVal::Int(technology(&info.battery_type) as i32)),
        Property::CycleCount => Ok(PropVal::Int(info.cycle_count as i32)),
        Property::VoltageMinDesign => known(info.design_voltage),
        Property::VoltageNow => known(state.voltage_now),
        Property::CurrentNow | Property::PowerNow => known(state.rate_now),
        Property::ChargeFullDesign | Property::EnergyFullDesign => valid(info.design_capacity),
        Property::ChargeFull | Property::EnergyFull => valid(info.full_charge_capacity),
        Property::ChargeNow | Property::EnergyNow => known(state.capacity_now),
        Property::Capacity => capacity_percent(info, state)
            .map(PropVal::Int).ok_or(VfsError::Enodev),
        Property::CapacityLevel => Ok(PropVal::Int(
            capacity_level(info, state, reading.alarm) as i32)),
        Property::ModelName => Ok(PropVal::Str(info.model_number.clone())),
        Property::Manufacturer => Ok(PropVal::Str(info.oem_info.clone())),
        Property::SerialNumber => Ok(PropVal::Str(info.serial_number.clone())),
        _ => Err(VfsError::Einval),
    }
}

/// A reported field, converted to micro-units. # C: O(1)
fn known(value: u32) -> KResult<PropVal> {
    if value == VALUE_UNKNOWN { return Err(VfsError::Enodev); }
    Ok(PropVal::Int(to_micro(value)))
}

/// A capacity reference, which must also be non-zero to mean anything.
/// # C: O(1)
fn valid(value: u32) -> KResult<PropVal> {
    if !capacity_valid(value) { return Err(VfsError::Enodev); }
    Ok(PropVal::Int(to_micro(value)))
}

/// Device name published to the class. Firmware names the battery object; the
/// class must not invent an index of its own, because a machine with two
/// batteries would then renumber them on every boot order change. # C: O(n)
pub fn device_name(namespace_path: &str) -> String {
    let leaf = namespace_path.rsplit('.').next().unwrap_or(namespace_path);
    String::from(leaf.trim_end_matches('_'))
}
