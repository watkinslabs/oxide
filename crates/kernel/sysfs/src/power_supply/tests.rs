use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Mutex;

use power_supply::{Property, PropVal, PsyType, Status, SupplyDesc, SupplyOps, Technology};
use vfs::{KResult, VfsError};

use super::CLASS;
use crate::virtual_class::{make_class_dir, make_virtual_dir};

/// The class registry is global; serialise the tests that populate it.
static CLASS_LOCK: Mutex<()> = Mutex::new(());

const ATTR_BUFFER_BYTES: usize = 256;

struct Battery;

impl SupplyOps for Battery {
    fn get_property(&self, prop: Property) -> KResult<PropVal> {
        match prop {
            Property::Status => Ok(PropVal::Int(Status::Discharging as i32)),
            Property::Present => Ok(PropVal::Int(1)),
            Property::Technology => Ok(PropVal::Int(Technology::LiIon as i32)),
            Property::Capacity => Ok(PropVal::Int(73)),
            Property::VoltageNow => Ok(PropVal::Int(11_500_000)),
            Property::ChargeFullDesign => Ok(PropVal::Int(5_000_000)),
            Property::ModelName => Ok(PropVal::Str(String::from("OXP-1"))),
            _ => Err(VfsError::Einval),
        }
    }
}

fn declared() -> Vec<Property> {
    alloc::vec![
        Property::Status, Property::Present, Property::Technology, Property::Capacity,
        Property::VoltageNow, Property::ChargeFullDesign, Property::ModelName,
    ]
}

fn read_all(inode: &vfs::InodeRef) -> Vec<u8> {
    let mut buf = [0u8; ATTR_BUFFER_BYTES];
    let read = inode.read(0, &mut buf).expect("attribute read");
    buf[..read].to_vec()
}

#[test]
fn a_registered_battery_appears_in_the_class_and_answers_its_attributes() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let psy = power_supply::register(
        SupplyDesc::new("BAT0", PsyType::Battery, declared()), Arc::new(Battery),
    ).expect("register");

    let class_dir = make_class_dir(&CLASS);
    let link = class_dir.lookup("BAT0").expect("class entry");
    assert_eq!(link.readlink().expect("readlink"),
               b"../../devices/virtual/power_supply/BAT0".to_vec());
    assert!(class_dir.lookup("BAT9").is_err());

    let virtual_dir = make_virtual_dir(&CLASS);
    let dev = virtual_dir.lookup("BAT0").expect("device dir");
    assert_eq!(read_all(&dev.lookup("capacity").expect("capacity")), b"73\n".to_vec());
    assert_eq!(read_all(&dev.lookup("status").expect("status")), b"Discharging\n".to_vec());
    assert_eq!(read_all(&dev.lookup("technology").expect("technology")), b"Li-ion\n".to_vec());
    assert_eq!(read_all(&dev.lookup("model_name").expect("model_name")), b"OXP-1\n".to_vec());
    assert_eq!(read_all(&dev.lookup("type").expect("type")), b"Battery\n".to_vec());
    assert_eq!(read_all(&dev.lookup("voltage_now").expect("voltage_now")),
               b"11500000\n".to_vec(), "microvolts, not millivolts");
    assert_eq!(read_all(&dev.lookup("charge_full_design").expect("charge_full_design")),
               b"5000000\n".to_vec(), "microamp-hours, not milliamp-hours");

    assert_eq!(dev.lookup("subsystem").expect("subsystem").readlink().expect("readlink"),
               b"../../../../class/power_supply".to_vec());

    assert!(power_supply::unregister(&psy));
}

#[test]
fn an_undeclared_attribute_is_absent_from_the_directory() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let psy = power_supply::register(
        SupplyDesc::new("BAT1", PsyType::Battery, declared()), Arc::new(Battery),
    ).expect("register");

    let dev = make_virtual_dir(&CLASS).lookup("BAT1").expect("device dir");
    assert!(dev.lookup("online").is_err(), "a battery must not publish a mains attribute");
    assert!(dev.lookup("energy_now").is_err());
    assert!(dev.lookup("cycle_count").is_err());
    assert_eq!(dev.lookup("capacity").expect("capacity").perm(), Some(0o444));

    assert!(power_supply::unregister(&psy));
}

#[test]
fn the_uevent_attribute_names_the_supply_and_accepts_a_trigger() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let psy = power_supply::register(
        SupplyDesc::new("BAT2", PsyType::Battery, declared()), Arc::new(Battery),
    ).expect("register");

    let dev = make_virtual_dir(&CLASS).lookup("BAT2").expect("device dir");
    let uevent = dev.lookup("uevent").expect("uevent");
    let body = String::from_utf8(read_all(&uevent)).expect("utf8");
    assert!(body.starts_with("POWER_SUPPLY_NAME=BAT2\n"), "{body}");
    assert!(body.contains("POWER_SUPPLY_TYPE=Battery\n"), "{body}");
    assert!(body.contains("POWER_SUPPLY_CAPACITY=73\n"), "{body}");
    assert_eq!(uevent.perm(), Some(0o644));
    assert_eq!(uevent.write(0, b"change\n"), Ok(7));

    assert!(power_supply::unregister(&psy));
}

#[test]
fn an_unregistered_supply_leaves_no_directory_behind() {
    let _serial = CLASS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let psy = power_supply::register(
        SupplyDesc::new("BAT3", PsyType::Battery, declared()), Arc::new(Battery),
    ).expect("register");
    let dev = make_virtual_dir(&CLASS).lookup("BAT3").expect("device dir");

    assert!(power_supply::unregister(&psy));

    assert!(make_class_dir(&CLASS).lookup("BAT3").is_err());
    assert!(make_virtual_dir(&CLASS).lookup("BAT3").is_err());
    assert!(dev.lookup("capacity").is_err(), "a retained dir must not answer for a gone supply");
}
