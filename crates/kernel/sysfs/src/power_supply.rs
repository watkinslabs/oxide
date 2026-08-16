// `/sys/class/power_supply` — projection of the power-supply class registry.
// Every decision (which attributes a supply publishes, what they render, what
// a write does, the uevent environment) belongs to the `power-supply` crate;
// this module owns inodes and the class change hook only.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::{KResult, VfsError};

use crate::virtual_class::{self, VirtualClass};

static CLASS: VirtualClass = VirtualClass {
    name: power_supply::CLASS_NAME,
    devices: supply_names,
    attrs: supply_attrs,
    links: no_links,
    show: supply_show,
    store: supply_store,
    uevent_env: supply_uevent_env,
    ino_class: crate::ids::POWER_SUPPLY_CLASS,
    ino_virtual: crate::ids::POWER_SUPPLY_VIRT,
    ino_device: crate::ids::POWER_SUPPLY_DIR,
    ino_attr: crate::ids::POWER_SUPPLY_ATTR,
    ino_link: crate::ids::POWER_SUPPLY_LINK,
};

fn supply_names() -> Vec<String> {
    power_supply::supplies().iter().map(|psy| String::from(psy.name())).collect()
}

fn no_links(_name: &str) -> Vec<(String, String)> { Vec::new() }

fn supply_attrs(name: &str) -> Option<Vec<(String, u16)>> {
    let psy = power_supply::by_name(name)?;
    Some(power_supply::attrs::visible_attrs(&psy).into_iter()
        .map(|(attr, mode)| (String::from(attr), mode)).collect())
}

fn supply_show(name: &str, attr: &str) -> KResult<Vec<u8>> {
    let psy = power_supply::by_name(name).ok_or(VfsError::Enoent)?;
    power_supply::attrs::show(&psy, attr)
}

fn supply_store(name: &str, attr: &str, buf: &[u8]) -> KResult<usize> {
    let psy = power_supply::by_name(name).ok_or(VfsError::Enoent)?;
    power_supply::attrs::store(&psy, attr, buf)
}

fn supply_uevent_env(name: &str) -> Option<Vec<String>> {
    let psy = power_supply::by_name(name)?;
    Some(power_supply::attrs::uevent_env(&psy))
}

/// Class change: a supply's state moved, so every consumer must re-read.
const CHANGE_ACTION: &str = "change";

fn on_change(name: &str) { virtual_class::emit_uevent(&CLASS, CHANGE_ACTION, name); }

/// Register `/sys/class/power_supply` and route class changes to uevents.
/// # C: O(1)
pub fn init() {
    virtual_class::register(&CLASS);
    power_supply::set_change_hook(on_change);
}

#[cfg(test)]
mod tests;
