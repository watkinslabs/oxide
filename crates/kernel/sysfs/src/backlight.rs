// `/sys/class/backlight` — projection of the backlight class registry. Every
// decision (attribute set, brightness validation, blank rules, event source)
// belongs to the `backlight` crate; this module owns inodes and the class
// change hook only.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::{KResult, VfsError};

use crate::virtual_class::{self, VirtualClass};

static CLASS: VirtualClass = VirtualClass {
    name: backlight::CLASS_NAME,
    devices: device_names,
    attrs: device_attrs,
    links: no_links,
    show: device_show,
    store: device_store,
    uevent_env: device_uevent_env,
    ino_class: crate::ids::BACKLIGHT_CLASS,
    ino_virtual: crate::ids::BACKLIGHT_VIRT,
    ino_device: crate::ids::BACKLIGHT_DIR,
    ino_attr: crate::ids::BACKLIGHT_ATTR,
    ino_link: crate::ids::BACKLIGHT_LINK,
};

fn device_names() -> Vec<String> {
    backlight::devices().iter().map(|dev| String::from(dev.name())).collect()
}

fn no_links(_name: &str) -> Vec<(String, String)> { Vec::new() }

fn device_attrs(name: &str) -> Option<Vec<(String, u16)>> {
    backlight::by_name(name)?;
    Some(backlight::attrs::ATTRS.iter()
        .map(|attr| (String::from(attr.name), attr.mode)).collect())
}

fn device_show(name: &str, attr: &str) -> KResult<Vec<u8>> {
    let dev = backlight::by_name(name).ok_or(VfsError::Enoent)?;
    backlight::attrs::show(&dev, attr)
}

fn device_store(name: &str, attr: &str, buf: &[u8]) -> KResult<usize> {
    let dev = backlight::by_name(name).ok_or(VfsError::Enoent)?;
    backlight::attrs::store(&dev, attr, buf)
}

fn device_uevent_env(name: &str) -> Option<Vec<String>> {
    let dev = backlight::by_name(name)?;
    Some(backlight::attrs::uevent_env(&dev))
}

/// Class change: the level moved, so a consumer's cached value is stale.
const CHANGE_ACTION: &str = "change";
/// The class change hook reports why; it becomes the event's `SOURCE=`.
const SOURCE_VAR: &str = "SOURCE=";

fn on_change(name: &str, source: &str) {
    let Some(mut env) = device_uevent_env(name) else { return; };
    let mut line = String::from(SOURCE_VAR);
    line.push_str(source);
    env.insert(0, line);
    let refs: Vec<&str> = env.iter().map(String::as_str).collect();
    ::netlink::emit_uevent_with_env(
        CHANGE_ACTION,
        &alloc::format!("/devices/virtual/{}/{name}", backlight::CLASS_NAME),
        backlight::CLASS_NAME,
        &refs,
    );
}

/// Register `/sys/class/backlight` and route class changes to uevents.
/// # C: O(1)
pub fn init() {
    virtual_class::register(&CLASS);
    backlight::set_change_hook(on_change);
}

#[cfg(test)]
mod tests;
