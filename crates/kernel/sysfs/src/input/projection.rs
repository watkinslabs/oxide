use alloc::string::String;
use alloc::vec::Vec;

use super::model::{input_by_addr, parent_name, InputDevInfo};

fn event_uevent_env(info: &InputDevInfo) -> Vec<String> {
    alloc::vec![
        alloc::format!("MAJOR={}", info.dev_t.0),
        alloc::format!("MINOR={}", info.dev_t.1),
        alloc::format!("DEVNAME={}", info.devname),
    ]
}

fn emit_model_events(action: &str, dev: &drv::Device, parent_first: bool) {
    let Some(info) = input_by_addr(&dev.addr) else { return; };
    let Some(parent_canon) = info.sysfs_parent_canon() else { return; };
    let Some(event_canon) = info.sysfs_event_canon() else { return; };
    let parent_path = alloc::format!("/{parent_canon}");
    let event_path = alloc::format!("/{event_canon}");
    let parent_env = input::uevent_env_for(&info.model);
    let event_env = event_uevent_env(&info);
    let parent_refs: Vec<&[u8]> = parent_env.iter().map(|entry| entry.as_slice()).collect();
    let event_refs: Vec<&str> = event_env.iter().map(|entry| entry.as_str()).collect();
    let emit_parent = || {
        ::netlink::emit_uevent_with_env_bytes(action, &parent_path, "input", &parent_refs);
    };
    let emit_event = || {
        ::netlink::emit_uevent_with_env(action, &event_path, "input", &event_refs);
    };
    if parent_first {
        emit_parent();
        emit_event();
    } else {
        emit_event();
        emit_parent();
    }
}

/// Emit Linux inputN then eventN add events. # C: O(cap bits + path length)
pub(crate) fn emit_device_add(dev: &drv::Device) {
    emit_model_events("add", dev, true);
}

/// Emit Linux eventN then inputN remove events. # C: O(cap bits + path length)
pub(crate) fn emit_device_remove(dev: &drv::Device) {
    emit_model_events("remove", dev, false);
}

/// Reverse `/sys/dev/char` link for an evdev node. # C: O(path length)
pub(crate) fn dev_index_target(dev: &drv::Device) -> Option<Vec<u8>> {
    if dev.bus != "input" { return None; }
    let info = input_by_addr(&dev.addr)?;
    Some(alloc::format!("../../{}", info.sysfs_event_canon()?).into_bytes())
}

/// Canonical Linux DEVPATH for an evdev model node. # C: O(path length)
pub(crate) fn dev_devpath(dev: &drv::Device) -> Option<String> {
    if dev.bus != "input" { return None; }
    let info = input_by_addr(&dev.addr)?;
    Some(alloc::format!("/{}", info.sysfs_event_canon()?))
}

/// Cached sysfs paths invalidated when an input node is removed. # C: O(path length)
pub(crate) fn related_paths(dev: &drv::Device) -> Vec<String> {
    let Some(info) = input_by_addr(&dev.addr) else { return Vec::new(); };
    let Some(parent) = info.sysfs_parent_canon() else { return Vec::new(); };
    let Some(event) = info.sysfs_event_canon() else { return Vec::new(); };
    let mut paths = alloc::vec![
        alloc::format!("/{event}"),
        alloc::format!("/{parent}"),
        alloc::format!("/class/input/{}", info.addr),
        alloc::format!("/class/input/{}", parent_name(&info)),
    ];
    if info.device.parent().is_some() {
        if let Some((container, _)) = parent.rsplit_once('/') {
            paths.push(alloc::format!("/{container}"));
        }
    }
    paths
}
