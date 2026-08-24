// `/sys/class/hwmon` — projection of the power-supply hwmon bridge.
// The power-supply crate owns property selection, units and writes; this file
// owns only the virtual-class filesystem projection.

use alloc::string::String;
use alloc::vec::Vec;
use vfs::KResult;

use crate::virtual_class::{self, VirtualClass};

static CLASS: VirtualClass = VirtualClass {
    name: power_supply::hwmon::CLASS_NAME,
    devices: power_supply::hwmon::devices,
    attrs: attrs,
    links: no_links,
    show,
    store,
    uevent_env: power_supply::hwmon::uevent_env,
    ino_class: crate::ids::HWMON_CLASS,
    ino_virtual: crate::ids::HWMON_VIRT,
    ino_device: crate::ids::HWMON_DIR,
    ino_attr: crate::ids::HWMON_ATTR,
    ino_link: crate::ids::HWMON_LINK,
};

fn no_links(_name: &str) -> Vec<(String, String)> { Vec::new() }

fn attrs(name: &str) -> Option<Vec<(String, u16)>> {
    power_supply::hwmon::attrs(name)
}

fn show(name: &str, attr: &str) -> KResult<Vec<u8>> {
    power_supply::hwmon::show(name, attr)
}

fn store(name: &str, attr: &str, buf: &[u8]) -> KResult<usize> {
    power_supply::hwmon::store(name, attr, buf)
}

/// Register `/sys/class/hwmon` and its virtual-device projection. # C: O(1)
pub fn init() { virtual_class::register(&CLASS); }

#[cfg(test)]
mod tests;
