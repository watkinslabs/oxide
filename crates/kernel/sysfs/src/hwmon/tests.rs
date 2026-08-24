use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Mutex;

use power_supply::{Property, PropVal, PsyType, SupplyDesc, SupplyOps};
use vfs::{KResult, VfsError};

use super::CLASS;
use crate::virtual_class::{make_class_dir, make_virtual_dir};

static LOCK: Mutex<()> = Mutex::new(());

struct Battery;
impl SupplyOps for Battery {
    fn get_property(&self, prop: Property) -> KResult<PropVal> {
        match prop {
            Property::VoltageNow => Ok(PropVal::Int(11_500_000)),
            Property::Temp => Ok(PropVal::Int(250)),
            _ => Err(VfsError::Einval),
        }
    }
}

fn read(inode: &vfs::InodeRef) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = inode.read(0, &mut buf).expect("read");
    buf[..n].to_vec()
}

#[test]
fn class_projects_power_supply_hwmon_values_and_name() {
    let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let psy = power_supply::register(
        SupplyDesc::new("HW-BAT", PsyType::Battery,
            alloc::vec![Property::VoltageNow, Property::Temp]),
        Arc::new(Battery),
    ).expect("register");
    let name = alloc::format!("hwmon{}", psy.hwmon_id().expect("hwmon id"));
    let link = make_class_dir(&CLASS).lookup(&name).expect("class device");
    assert!(link.readlink().expect("link").ends_with(name.as_bytes()));
    let device = make_virtual_dir(&CLASS).lookup(&name).expect("virtual device");
    assert_eq!(read(&device.lookup("name").expect("name")), b"HW_BAT\n".to_vec());
    assert_eq!(read(&device.lookup("in0_input").expect("voltage")), b"11500\n".to_vec());
    assert_eq!(read(&device.lookup("temp1_input").expect("temperature")), b"25000\n".to_vec());
    assert!(power_supply::unregister(&psy));
    assert!(make_class_dir(&CLASS).lookup(&name).is_err());
}
