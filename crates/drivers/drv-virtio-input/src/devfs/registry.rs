use alloc::sync::Arc;

use crate::devfs::fileops::make_evdev_inode_for;
use crate::devfs::shared::{
    current_endpoint, publish_endpoint, unpublish_endpoint, unpublish_exact, EvdevEndpoint,
    EVDEV_DEVICES,
};
use crate::evdev_queue::MAX_EVDEV;
use crate::consts::{EVENT_MINOR_BASE, INPUT_MAJOR};

const INPUT_OBJECT_PREFIX: &str = "input";

fn dispatch_packet(id: u32, is_pointer: bool, values: &[input::InputValue]) {
    crate::evdev_queue::push_packet(id, values);
    if !is_pointer {
        for value in values {
            if value.ev_type == crate::EV_KEY {
                crate::drain::handle_key_event(value.code, value.value != 0);
            }
        }
    }
}

fn dispatch_output(
    device_key: input::VirtioChildDeviceKey,
    output: &input::OutputBatch,
) {
    crate::drain::send_output_batch(device_key, output)
        .expect("published input device owns a live status queue");
}

pub fn init() {
    devfs::register_dir("/dev/input");
    input::set_evdev_hooks(input::EvdevHooks {
        register: Some(|id| register_node(id, None)),
        unregister: Some(unregister_node),
        push_packet: Some(dispatch_packet),
    });
    input::set_output_hook(dispatch_output);
}

pub fn register_node(id: u32, parent: Option<&Arc<drv::Device>>) -> bool {
    if (id as usize) >= MAX_EVDEV {
        return false;
    }
    let slot = id as usize;
    if EVDEV_DEVICES.lock()[slot].is_some() {
        return false;
    }
    let endpoint = match input::device(id) {
        Some(model) => EvdevEndpoint::new(model.device_key, model.input_id, model.evdev_id),
        None => {
            #[cfg(not(test))]
            return false;
            #[cfg(test)]
            crate::devfs::shared::test_endpoint(id, u32::MAX - id)
        }
    };
    if !publish_endpoint(Arc::clone(&endpoint)) { return false; }
    let inode_endpoint = Arc::clone(&endpoint);
    let factory: drv::NodeFactory =
        Arc::new(move || make_evdev_inode_for(Arc::clone(&inode_endpoint)));
    let input_id = endpoint.identity().input_id;
    let sysfs_relpath = if parent.is_some() {
        alloc::format!(
            "{INPUT_OBJECT_PREFIX}/{INPUT_OBJECT_PREFIX}{input_id}/event{id}",
        )
    } else {
        alloc::format!("{INPUT_OBJECT_PREFIX}{input_id}/event{id}")
    };
    let mut dev = drv::Device::new("input", alloc::format!("event{id}"), 0, 0, id)
        .with_devnode("input", alloc::format!("input/event{id}"), Some((INPUT_MAJOR, EVENT_MINOR_BASE + id)))
        .with_node_factory(factory)
        .with_sysfs_relpath(sysfs_relpath);
    if let Some(parent) = parent {
        dev = dev.with_parent(parent.bus, parent.addr.clone());
    }
    let candidate = Arc::new(dev);
    let result = match parent {
        Some(parent) => drv::try_device_add_with_parent(candidate, parent),
        None => drv::try_device_add(candidate),
    };
    let dev = match result {
        Ok(dev) => dev,
        Err(_) => {
            let _ = unpublish_exact(&endpoint);
            return false;
        }
    };
    EVDEV_DEVICES.lock()[slot] = Some(Arc::clone(&dev));
    let still_current = current_endpoint(id)
        .is_some_and(|current| Arc::ptr_eq(&current, &endpoint) && current.is_alive());
    if still_current { return true; }
    let removed = {
        let mut devices = EVDEV_DEVICES.lock();
        if devices[slot].as_ref().is_some_and(|current| Arc::ptr_eq(current, &dev)) {
            devices[slot].take()
        } else {
            None
        }
    };
    if let Some(removed) = removed { drv::device_del(&removed); }
    false
}

pub fn unregister_node(id: u32) -> bool {
    if (id as usize) >= MAX_EVDEV {
        return false;
    }
    let slot = id as usize;
    let endpoint = unpublish_endpoint(id);
    let dev = EVDEV_DEVICES.lock()[slot].take();
    if let Some(dev) = dev {
        drv::device_del(&dev);
        true
    } else {
        endpoint.is_some()
    }
}

pub(crate) fn model_device(id: u32) -> Option<Arc<drv::Device>> {
    EVDEV_DEVICES.lock().get(id as usize)?.clone()
}
