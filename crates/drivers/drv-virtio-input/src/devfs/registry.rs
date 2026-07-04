use alloc::sync::Arc;

use crate::devfs::fileops::make_evdev_inode;
use crate::devfs::shared::{EVDEV_DEVICES, EVDEV_GRABS, EVDEV_NODES};
use crate::evdev_queue::MAX_EVDEV;

pub fn init() {
    devfs::register_dir("/dev/input");
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
    let mut dev = drv::Device::new("input", alloc::format!("event{id}"), 0, 0, id)
        .with_devnode("input", alloc::format!("input/event{id}"), Some((13, 64 + id)))
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
