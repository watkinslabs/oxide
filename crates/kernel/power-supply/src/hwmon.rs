//! The power-supply-owned hwmon projection.
//!
//! Hwmon has no second reading cache: visibility, property selection, unit
//! conversion and writes all resolve back to the canonical power-supply.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtol, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::registry::supplies;
use crate::supply::{PowerSupply, PropVal};
use crate::uapi::Property;

const HWMON_PREFIX: &str = "hwmon";
pub const CLASS_NAME: &str = HWMON_PREFIX;
const RO: u16 = 0o444;
const OWNER_WRITE: u16 = 0o200;

#[derive(Copy, Clone)]
enum Scale { Micro, Power, Temp }

#[derive(Copy, Clone)]
struct Attr { name: &'static str, prop: Option<Property>, label: Option<&'static str>,
              writable: bool, scale: Scale }

const ATTRS: &[Attr] = &[
    Attr { name: "in0_average", prop: Some(Property::VoltageAvg), label: None, writable: false, scale: Scale::Micro },
    Attr { name: "in0_min", prop: Some(Property::VoltageMin), label: None, writable: true, scale: Scale::Micro },
    Attr { name: "in0_max", prop: Some(Property::VoltageMax), label: None, writable: true, scale: Scale::Micro },
    Attr { name: "in0_input", prop: Some(Property::VoltageNow), label: None, writable: false, scale: Scale::Micro },
    Attr { name: "curr1_average", prop: Some(Property::CurrentAvg), label: None, writable: false, scale: Scale::Micro },
    Attr { name: "curr1_max", prop: Some(Property::CurrentMax), label: None, writable: true, scale: Scale::Micro },
    Attr { name: "curr1_input", prop: Some(Property::CurrentNow), label: None, writable: false, scale: Scale::Micro },
    Attr { name: "power1_input", prop: Some(Property::PowerNow), label: None, writable: false, scale: Scale::Power },
    Attr { name: "power1_average", prop: Some(Property::PowerAvg), label: None, writable: false, scale: Scale::Power },
    Attr { name: "temp1_input", prop: Some(Property::Temp), label: None, writable: false, scale: Scale::Temp },
    Attr { name: "temp1_max", prop: Some(Property::TempMax), label: None, writable: true, scale: Scale::Temp },
    Attr { name: "temp1_min", prop: Some(Property::TempMin), label: None, writable: true, scale: Scale::Temp },
    Attr { name: "temp1_min_alarm", prop: Some(Property::TempAlertMin), label: None, writable: true, scale: Scale::Temp },
    Attr { name: "temp1_max_alarm", prop: Some(Property::TempAlertMax), label: None, writable: true, scale: Scale::Temp },
    Attr { name: "temp1_label", prop: None, label: Some("temp"), writable: false, scale: Scale::Temp },
    Attr { name: "temp2_input", prop: Some(Property::TempAmbient), label: None, writable: false, scale: Scale::Temp },
    Attr { name: "temp2_min_alarm", prop: Some(Property::TempAmbientAlertMin), label: None, writable: true, scale: Scale::Temp },
    Attr { name: "temp2_max_alarm", prop: Some(Property::TempAmbientAlertMax), label: None, writable: true, scale: Scale::Temp },
    Attr { name: "temp2_label", prop: None, label: Some("ambient temp"), writable: false, scale: Scale::Temp },
];

/// Whether a supply declares any property the power-supply hwmon bridge owns.
/// # C: O(N_declared)
pub fn has_properties(psy: &PowerSupply) -> bool {
    ATTRS.iter().any(|attr| attr.prop.is_some_and(|prop| psy.has_property(prop)))
}

/// Names of the live hwmon devices, in their assigned instance order. # C: O(N_supplies)
pub fn devices() -> Vec<String> {
    supplies().into_iter().filter_map(|psy| psy.hwmon_id().map(|id| name(id))).collect()
}

fn name(id: u32) -> String { alloc::format!("{HWMON_PREFIX}{id}") }

fn supply(name: &str) -> Option<Arc<PowerSupply>> {
    let id = name.strip_prefix(HWMON_PREFIX)?.parse::<u32>().ok()?;
    supplies().into_iter().find(|psy| psy.hwmon_id() == Some(id))
}

fn attr(name: &str) -> Option<&'static Attr> { ATTRS.iter().find(|attr| attr.name == name) }

fn temp_channel_has_input(psy: &PowerSupply, channel: u8) -> bool {
    ATTRS.iter().any(|attr| {
        let right_channel = match channel { 1 => attr.name.starts_with("temp1_"), 2 => attr.name.starts_with("temp2_"), _ => false };
        right_channel && attr.prop.is_some_and(|prop| psy.has_property(prop))
    })
}

/// Attribute names and modes for one hwmon device. # C: O(N_attrs * N_declared)
pub fn attrs(name: &str) -> Option<Vec<(String, u16)>> {
    let psy = supply(name)?;
    let mut out = Vec::new();
    out.push((String::from("name"), RO));
    for attr in ATTRS {
        let visible = match (attr.prop, attr.label) {
            (Some(prop), _) => psy.has_property(prop),
            (None, Some(_)) => temp_channel_has_input(&psy, if attr.name.starts_with("temp1_") { 1 } else { 2 }),
            (None, None) => false,
        };
        if !visible { continue; }
        let mode = if attr.prop.is_some_and(|prop| attr.writable && psy.property_is_writeable(prop)) {
            RO | OWNER_WRITE
        } else { RO };
        out.push((String::from(attr.name), mode));
    }
    Some(out)
}

fn sanitize_name(psy: &PowerSupply) -> String { psy.name().replace('-', "_") }

fn scale_read(value: i32, scale: Scale) -> KResult<i32> {
    match scale {
        Scale::Micro => Ok(div_round_closest(value, 1000)),
        Scale::Power => Ok(value),
        Scale::Temp => value.checked_mul(100).ok_or(VfsError::Erange),
    }
}

fn scale_write(value: i64, scale: Scale) -> KResult<i32> {
    let value = match scale {
        Scale::Micro => value.checked_mul(1000).ok_or(VfsError::Erange)?,
        Scale::Power => value,
        Scale::Temp => div_round_closest_i64(value, 100),
    };
    i32::try_from(value).map_err(|_| VfsError::Erange)
}

fn div_round_closest(value: i32, divisor: i32) -> i32 {
    div_round_closest_i64(i64::from(value), i64::from(divisor)) as i32
}

fn div_round_closest_i64(value: i64, divisor: i64) -> i64 {
    if value < 0 { -((-value + divisor / 2) / divisor) } else { (value + divisor / 2) / divisor }
}

/// Read one hwmon attribute through the power-supply provider. # C: O(driver)
pub fn show(name: &str, attr_name: &str) -> KResult<Vec<u8>> {
    let psy = supply(name).ok_or(VfsError::Enoent)?;
    if attr_name == "name" { return Ok(alloc::format!("{}\n", sanitize_name(&psy)).into_bytes()); }
    let attr = attr(attr_name).ok_or(VfsError::Enoent)?;
    if let Some(label) = attr.label {
        if !attrs(name).is_some_and(|items| items.iter().any(|(item, _)| item == attr_name)) { return Err(VfsError::Enoent); }
        return Ok(alloc::format!("{label}\n").into_bytes());
    }
    let prop = attr.prop.ok_or(VfsError::Enoent)?;
    if !psy.has_property(prop) { return Err(VfsError::Enoent); }
    let value = psy.get_property(prop)?.as_int()?;
    Ok(alloc::format!("{}\n", scale_read(value, attr.scale)?).into_bytes())
}

/// Write one writable hwmon attribute back to its power-supply property. # C: O(driver)
pub fn store(name: &str, attr_name: &str, buf: &[u8]) -> KResult<usize> {
    let psy = supply(name).ok_or(VfsError::Enoent)?;
    let attr = attr(attr_name).ok_or(VfsError::Enoent)?;
    let prop = attr.prop.filter(|prop| attr.writable && psy.property_is_writeable(*prop))
        .ok_or(VfsError::Eacces)?;
    let value = kstrtol(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
    psy.set_property(prop, &PropVal::Int(scale_write(value, attr.scale)?))?;
    Ok(buf.len())
}

/// Uevent environment for one hwmon device. # C: O(1)
pub fn uevent_env(name: &str) -> Option<Vec<String>> {
    let psy = supply(name)?;
    Some(alloc::vec![alloc::format!("NAME={}", sanitize_name(&psy))])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{clear_for_tests, register, unregister};
    use crate::supply::{SupplyDesc, SupplyOps};
    use crate::values::PsyType;
    use core::sync::atomic::AtomicU32;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    struct Ops { writes: AtomicU32 }
    impl SupplyOps for Ops {
        fn get_property(&self, prop: Property) -> KResult<PropVal> {
            match prop {
                Property::VoltageNow => Ok(PropVal::Int(12_345_000)),
                Property::Temp => Ok(PropVal::Int(253)),
                Property::TempMax => Ok(PropVal::Int(600)),
                _ => Err(VfsError::Einval),
            }
        }
        fn set_property(&self, prop: Property, value: &PropVal) -> KResult<()> {
            if prop == Property::TempMax && value == &PropVal::Int(700) { self.writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed); Ok(()) }
            else { Err(VfsError::Einval) }
        }
        fn property_is_writeable(&self, prop: Property) -> bool { prop == Property::TempMax }
    }

    #[test]
    fn hwmon_projects_declared_values_and_round_trips_writable_units() {
        let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let ops = Arc::new(Ops { writes: AtomicU32::new(0) });
        let psy = register(SupplyDesc::new("BAT-0", PsyType::Battery,
            alloc::vec![Property::VoltageNow, Property::Temp, Property::TempMax]), ops.clone()).expect("supply");
        let hw = psy.hwmon_id().map(name).expect("hwmon");
        assert_eq!(show(&hw, "name"), Ok(b"BAT_0\n".to_vec()));
        assert_eq!(show(&hw, "in0_input"), Ok(b"12345\n".to_vec()));
        assert_eq!(show(&hw, "temp1_input"), Ok(b"25300\n".to_vec()));
        assert_eq!(store(&hw, "temp1_max", b"70000\n"), Ok(6));
        assert_eq!(ops.writes.load(core::sync::atomic::Ordering::Relaxed), 1);
        assert!(attrs(&hw).unwrap().iter().any(|(attr, mode)| attr == "temp1_max" && *mode == (RO | OWNER_WRITE)));
        assert!(unregister(&psy));
        clear_for_tests();
    }
}
