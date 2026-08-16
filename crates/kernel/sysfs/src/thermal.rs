// `/sys/class/thermal` — projection of the thermal class. Both halves of the
// class, zones and cooling devices, live in one directory; which is which is a
// property of the name, and the `thermal` crate owns that distinction along
// with every attribute decision. This module owns inodes and the change hook.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::{KResult, VfsError};

use crate::virtual_class::{self, VirtualClass};

static CLASS: VirtualClass = VirtualClass {
    name: thermal::CLASS_NAME,
    devices: device_names,
    attrs: device_attrs,
    links: device_links,
    show: device_show,
    store: device_store,
    uevent_env: device_uevent_env,
    ino_class: crate::ids::THERMAL_CLASS,
    ino_virtual: crate::ids::THERMAL_VIRT,
    ino_device: crate::ids::THERMAL_DIR,
    ino_attr: crate::ids::THERMAL_ATTR,
    ino_link: crate::ids::THERMAL_LINK,
};

fn device_names() -> Vec<String> { thermal::device_names() }

fn device_attrs(name: &str) -> Option<Vec<(String, u16)>> { thermal::attrs::attrs(name) }

fn device_links(name: &str) -> Vec<(String, String)> { thermal::attrs::links(name) }

fn device_show(name: &str, attr: &str) -> KResult<Vec<u8>> {
    thermal::attrs::show(name, attr, now_ns()).map_err(|err| match err {
        VfsError::Enoent => VfsError::Enoent,
        other => other,
    })
}

fn device_store(name: &str, attr: &str, buf: &[u8]) -> KResult<usize> {
    thermal::attrs::store(name, attr, buf, now_ns())
}

fn device_uevent_env(name: &str) -> Option<Vec<String>> { thermal::attrs::uevent_env(name) }

/// The clock the occupancy statistics are measured against. # C: O(1)
fn now_ns() -> u64 { timekeeper::monotonic_ns() }

/// Class change: a temperature moved, a trip was crossed, or a cooling device
/// changed state. A thermal daemon watches for exactly this.
const CHANGE_ACTION: &str = "change";

fn on_change(name: &str) {
    virtual_class::emit_uevent(&CLASS, CHANGE_ACTION, name);
}

/// Environment a crossing publication carries beyond the device's own.
const CROSSING_NAME: &str = "NAME=";
const CROSSING_TEMP: &str = "TEMP=";
const CROSSING_TRIP: &str = "TRIP=";
const CROSSING_EVENT: &str = "EVENT=";

/// A governor that publishes crossings instead of cooling turns each one into
/// a class event naming the zone, its temperature and the trip.
/// # C: O(N_env)
fn on_crossing(name: &str, temp_mc: i32, trip: usize, direction: thermal::Direction) {
    let Some(mut env) = device_uevent_env(name) else { return; };
    env.push(alloc::format!("{CROSSING_NAME}{name}"));
    env.push(alloc::format!("{CROSSING_TEMP}{temp_mc}"));
    env.push(alloc::format!("{CROSSING_TRIP}{trip}"));
    env.push(alloc::format!("{CROSSING_EVENT}{}", match direction {
        thermal::Direction::Up => 1,
        thermal::Direction::Down => 0,
    }));
    let refs: Vec<&str> = env.iter().map(String::as_str).collect();
    ::netlink::emit_uevent_with_env(
        CHANGE_ACTION,
        &alloc::format!("/devices/virtual/{}/{name}", thermal::CLASS_NAME),
        thermal::CLASS_NAME,
        &refs,
    );
}

/// Register `/sys/class/thermal` and route class changes to uevents.
/// # C: O(1)
pub fn init() {
    virtual_class::register(&CLASS);
    thermal::set_change_hook(on_change);
    thermal::set_crossing_hook(on_crossing);
}
