// The `/sys/class/power_supply/<name>/` attribute contract: which files a
// given supply publishes, their modes, what each renders and what a write
// does. Visibility is per supply — a mains adapter must not grow a `capacity`
// file just because the class knows the property exists.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtol, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::format::{match_string, render};
use crate::supply::{PowerSupply, PropVal};
use crate::uapi::{Kind, Property, ATTRS};
use crate::values::UEVENT_PREFIX;

/// Base mode of every published attribute.
pub const RO_MODE: u16 = 0o444;
/// Owner-write bit added to a writable attribute.
pub const OWNER_WRITE: u16 = 0o200;
/// Mode of the always-present `uevent` attribute.
pub const UEVENT_MODE: u16 = 0o644;

/// Declared-value bitmask backing a multi-valued property. # C: O(1)
fn available_mask(psy: &PowerSupply, prop: Property) -> u32 {
    match prop {
        Property::ChargeTypes => psy.desc().charge_types,
        Property::ChargeBehaviour => psy.desc().charge_behaviours,
        Property::UsbType => psy.desc().usb_types,
        _ => 0,
    }
}

/// Mode of `prop`'s attribute for this supply, or zero when the supply does
/// not publish it at all. The category is always published: it is fixed at
/// registration, so it needs no driver and never becomes writable.
/// # C: O(N_declared)
pub fn visibility(psy: &PowerSupply, prop: Property) -> u16 {
    if prop == Property::Type { return RO_MODE; }
    if !psy.has_property(prop) { return 0; }
    if psy.property_is_writeable(prop) { RO_MODE | OWNER_WRITE } else { RO_MODE }
}

/// The attribute files this supply publishes, in class table order, each with
/// its mode. `uevent` is not a property and is added by the caller.
/// # C: O(N_props * N_declared)
pub fn visible_attrs(psy: &PowerSupply) -> Vec<(&'static str, u16)> {
    ATTRS.iter()
        .filter_map(|row| {
            let mode = visibility(psy, row.prop);
            if mode == 0 { None } else { Some((row.attr, mode)) }
        })
        .collect()
}

/// Attribute `show`. # C: O(driver)
pub fn show(psy: &Arc<PowerSupply>, name: &str) -> KResult<Vec<u8>> {
    let prop = Property::from_attr(name).ok_or(VfsError::Enoent)?;
    if visibility(psy, prop) == 0 { return Err(VfsError::Enoent); }
    let value = property_value(psy, prop)?;
    render(prop.kind(), &value, available_mask(psy, prop), false)
}

/// Read one property, answering `type` from the registration record rather
/// than from the driver. # C: O(driver)
fn property_value(psy: &Arc<PowerSupply>, prop: Property) -> KResult<PropVal> {
    if prop == Property::Type { return Ok(PropVal::Int(psy.ty() as i32)); }
    psy.get_property(prop)
}

/// Attribute `store`. # C: O(driver)
pub fn store(psy: &Arc<PowerSupply>, name: &str, buf: &[u8]) -> KResult<usize> {
    let prop = Property::from_attr(name).ok_or(VfsError::Enoent)?;
    if visibility(psy, prop) & OWNER_WRITE == 0 { return Err(VfsError::Eacces); }
    let value = match prop.kind() {
        Kind::Str => return Err(VfsError::Einval),
        Kind::Enum(table) | Kind::Available(table) => PropVal::Int(match_string(table, buf)?),
        Kind::Int => {
            let parsed = kstrtol(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
            PropVal::Int(i32::try_from(parsed).map_err(|_| VfsError::Erange)?)
        }
    };
    psy.set_property(prop, &value)?;
    Ok(buf.len())
}

/// Hotplug environment for one supply. The name comes first; a supply already
/// in teardown contributes nothing further, because reaching into a departing
/// driver to decorate its own removal event is how a removal races a read.
/// A property whose value is unsupported or momentarily unavailable is
/// skipped, so an absent battery still reports `POWER_SUPPLY_PRESENT=0`
/// instead of emitting no event at all. # C: O(N_declared * driver)
pub fn uevent_env(psy: &Arc<PowerSupply>) -> Vec<String> {
    let mut env = Vec::with_capacity(psy.desc().properties.len() + 2);
    env.push(var("NAME", psy.name().as_bytes()));
    if psy.removing() { return env; }
    if let Ok(body) = render(Property::Type.kind(), &PropVal::Int(psy.ty() as i32), 0, true) {
        env.push(var(&Property::Type.attr().to_ascii_uppercase(), &body));
    }
    for prop in psy.desc().properties.iter().copied() {
        if prop == Property::Type { continue; }
        let Ok(value) = psy.get_property(prop) else { continue; };
        let Ok(body) = render(prop.kind(), &value, available_mask(psy, prop), true) else { continue; };
        env.push(var(&prop.attr().to_ascii_uppercase(), &body));
    }
    env
}

/// `POWER_SUPPLY_<KEY>=<value>` with the rendered body's trailing newline
/// removed. # C: O(n)
fn var(key: &str, body: &[u8]) -> String {
    let mut line = String::from(UEVENT_PREFIX);
    line.push_str(key);
    line.push('=');
    let text = core::str::from_utf8(body).unwrap_or_default();
    line.push_str(text.strip_suffix('\n').unwrap_or(text));
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply::{SupplyDesc, SupplyOps};
    use crate::values::{PsyType, Status, Technology};

    struct Battery;

    impl SupplyOps for Battery {
        fn get_property(&self, prop: Property) -> KResult<PropVal> {
            match prop {
                Property::Status => Ok(PropVal::Int(Status::Discharging as i32)),
                Property::Present => Ok(PropVal::Int(1)),
                Property::Technology => Ok(PropVal::Int(Technology::LiIon as i32)),
                Property::Capacity => Ok(PropVal::Int(73)),
                Property::VoltageNow => Ok(PropVal::Int(11_500_000)),
                Property::ModelName => Ok(PropVal::Str(String::from("OXP-1"))),
                Property::ChargeControlEndThreshold => Ok(PropVal::Int(80)),
                Property::Temp => Err(VfsError::Enodata),
                _ => Err(VfsError::Einval),
            }
        }
        fn set_property(&self, _prop: Property, _value: &PropVal) -> KResult<()> { Ok(()) }
        fn property_is_writeable(&self, prop: Property) -> bool {
            prop == Property::ChargeControlEndThreshold
        }
    }

    fn battery() -> Arc<PowerSupply> {
        let desc = SupplyDesc::new("BAT0", PsyType::Battery, alloc::vec![
            Property::Status, Property::Present, Property::Technology, Property::Capacity,
            Property::VoltageNow, Property::ModelName, Property::ChargeControlEndThreshold,
            Property::Temp,
        ]);
        let psy = Arc::new(PowerSupply::new(desc, Arc::new(Battery)));
        psy.mark_initialized();
        psy
    }

    #[test]
    fn only_declared_properties_are_published() {
        let psy = battery();
        let names: Vec<&str> = visible_attrs(&psy).into_iter().map(|(name, _)| name).collect();
        assert_eq!(names, alloc::vec![
            "status", "present", "technology", "voltage_now", "charge_control_end_threshold",
            "capacity", "temp", "type", "model_name",
        ], "attributes are published in class-table order, not declaration order");
        assert!(!names.contains(&"online"), "a battery must not publish a mains attribute");
        assert!(!names.contains(&"energy_now"));
    }

    #[test]
    fn the_category_attribute_is_published_without_being_declared() {
        let psy = battery();
        assert!(!psy.has_property(Property::Type));
        assert_eq!(visibility(&psy, Property::Type), RO_MODE);
        assert_eq!(show(&psy, "type"), Ok(b"Battery\n".to_vec()));
    }

    #[test]
    fn a_writable_property_carries_the_owner_write_bit_and_nothing_else_does() {
        let psy = battery();
        assert_eq!(visibility(&psy, Property::ChargeControlEndThreshold), RO_MODE | OWNER_WRITE);
        assert_eq!(visibility(&psy, Property::Capacity), RO_MODE);
        assert_eq!(visibility(&psy, Property::Online), 0);
    }

    #[test]
    fn an_undeclared_attribute_is_absent_rather_than_unreadable() {
        let psy = battery();
        assert_eq!(show(&psy, "online"), Err(VfsError::Enoent));
        assert_eq!(show(&psy, "cycle_count"), Err(VfsError::Enoent));
        assert_eq!(show(&psy, "not_an_attribute"), Err(VfsError::Enoent));
    }

    #[test]
    fn values_render_in_the_class_units_and_spellings() {
        let psy = battery();
        assert_eq!(show(&psy, "status"), Ok(b"Discharging\n".to_vec()));
        assert_eq!(show(&psy, "present"), Ok(b"1\n".to_vec()));
        assert_eq!(show(&psy, "technology"), Ok(b"Li-ion\n".to_vec()));
        assert_eq!(show(&psy, "capacity"), Ok(b"73\n".to_vec()));
        assert_eq!(show(&psy, "voltage_now"), Ok(b"11500000\n".to_vec()),
                   "voltage is microvolts, not millivolts");
        assert_eq!(show(&psy, "model_name"), Ok(b"OXP-1\n".to_vec()));
    }

    #[test]
    fn a_write_to_a_read_only_attribute_is_eacces() {
        let psy = battery();
        assert_eq!(store(&psy, "capacity", b"50"), Err(VfsError::Eacces));
        assert_eq!(store(&psy, "type", b"Mains"), Err(VfsError::Eacces));
        assert_eq!(store(&psy, "online", b"1"), Err(VfsError::Eacces));
        assert_eq!(store(&psy, "model_name", b"x"), Err(VfsError::Eacces));
    }

    #[test]
    fn a_write_to_a_writable_integer_property_reaches_the_driver() {
        let psy = battery();
        assert_eq!(store(&psy, "charge_control_end_threshold", b"80\n"), Ok(3));
        assert_eq!(store(&psy, "charge_control_end_threshold", b"junk"), Err(VfsError::Einval));
    }

    #[test]
    fn the_uevent_names_the_supply_first_and_skips_unavailable_readings() {
        let psy = battery();
        let env = uevent_env(&psy);
        assert_eq!(env[0], "POWER_SUPPLY_NAME=BAT0");
        assert_eq!(env[1], "POWER_SUPPLY_TYPE=Battery");
        assert!(env.contains(&String::from("POWER_SUPPLY_STATUS=Discharging")));
        assert!(env.contains(&String::from("POWER_SUPPLY_PRESENT=1")));
        assert!(env.contains(&String::from("POWER_SUPPLY_CAPACITY=73")));
        assert!(env.contains(&String::from("POWER_SUPPLY_TECHNOLOGY=Li-ion")));
        assert!(env.contains(&String::from("POWER_SUPPLY_VOLTAGE_NOW=11500000")));
        assert!(env.contains(&String::from("POWER_SUPPLY_MODEL_NAME=OXP-1")));
        assert!(!env.iter().any(|line| line.starts_with("POWER_SUPPLY_TEMP=")),
                "an unavailable reading must be skipped, not emitted empty");
    }

    #[test]
    fn a_departing_supply_contributes_only_its_name() {
        let psy = battery();
        psy.mark_removing();
        assert_eq!(uevent_env(&psy), alloc::vec![String::from("POWER_SUPPLY_NAME=BAT0")]);
    }

    #[test]
    fn a_space_in_a_label_survives_as_one_uevent_token() {
        struct NotCharging;
        impl SupplyOps for NotCharging {
            fn get_property(&self, prop: Property) -> KResult<PropVal> {
                match prop {
                    Property::Status => Ok(PropVal::Int(Status::NotCharging as i32)),
                    _ => Err(VfsError::Einval),
                }
            }
        }
        let desc = SupplyDesc::new("BAT1", PsyType::Battery, alloc::vec![Property::Status]);
        let psy = Arc::new(PowerSupply::new(desc, Arc::new(NotCharging)));
        psy.mark_initialized();
        assert_eq!(show(&psy, "status"), Ok(b"Not_charging\n".to_vec()));
        let env = uevent_env(&psy);
        assert!(env.contains(&String::from("POWER_SUPPLY_STATUS=Not_charging")));
        for line in &env {
            assert!(!line.contains(' '), "{line} would split into two uevent tokens");
        }
    }
}
