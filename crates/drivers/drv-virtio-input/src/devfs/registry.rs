use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::devfs::fileops::make_evdev_inode;
use crate::devfs::shared::{EVDEV_DEVICES, EVDEV_GRABS, EVDEV_NODES};
use crate::evdev_queue::MAX_EVDEV;
use crate::consts::{EVENT_MINOR_BASE, INPUT_MAJOR};

pub fn init() {
    devfs::register_dir("/dev/input");
    input::set_evdev_hooks(input::EvdevHooks {
        register: Some(register_node),
        unregister: Some(unregister_node),
        push_event: Some(crate::evdev_queue::push_event),
    });
}

pub fn register_node(id: u32, parent: Option<(&'static str, alloc::string::String)>) -> bool {
    if (id as usize) >= MAX_EVDEV {
        return false;
    }
    let slot = id as usize;
    if EVDEV_DEVICES.lock()[slot].is_some() {
        return false;
    }
    let factory: drv::NodeFactory = Arc::new(move || make_evdev_inode(id));
    let env = input_uevent_env(id);
    let mut dev = drv::Device::new("input", alloc::format!("event{id}"), 0, 0, id)
        .with_devnode("input", alloc::format!("input/event{id}"), Some((INPUT_MAJOR, EVENT_MINOR_BASE + id)))
        .with_uevent_env(env)
        .with_node_factory(factory);
    if let Some((bus, addr)) = parent {
        dev = dev.with_parent(bus, addr);
    }
    let dev = match drv::try_device_add(Arc::new(dev)) {
        Ok(dev) => dev,
        Err(_) => return false,
    };
    EVDEV_DEVICES.lock()[slot] = Some(dev);
    true
}

fn utf8_payload(prefix: &str, bytes: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(bytes).ok()?.trim_end_matches('\0');
    if text.is_empty() { None } else { Some(alloc::format!("{prefix}=\"{text}\"")) }
}

fn input_uevent_env(id: u32) -> Vec<String> {
    let mut env = Vec::new();
    let Some(dev) = crate::device(id) else { return env; };
    env.push(alloc::format!(
        "PRODUCT={:x}/{:x}/{:x}/{:x}",
        dev.ids.bustype, dev.ids.vendor, dev.ids.product, dev.ids.version,
    ));
    if let Some(name) = utf8_payload("NAME", &dev.name[..dev.name_len]) {
        env.push(name);
    }
    if let Some(serial) = utf8_payload("UNIQ", &dev.serial[..dev.serial_len]) {
        env.push(serial);
    }
    env
}

pub fn unregister_node(id: u32) -> bool {
    if (id as usize) >= MAX_EVDEV {
        return false;
    }
    let slot = id as usize;
    EVDEV_NODES.lock()[slot] = None;
    EVDEV_GRABS.lock()[slot] = 0;
    let dev = EVDEV_DEVICES.lock()[slot].take();
    if let Some(dev) = dev {
        drv::device_del(&dev);
        true
    } else {
        false
    }
}
