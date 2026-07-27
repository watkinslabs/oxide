#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod registry;
mod types;

pub use registry::{
    clear_devices_for_tests, count, device, devices_snapshot, evdev_id_for_device, install, is_pointer, name_of,
    next_free_evdev_id, publish_evdev, push_evdev_event, remove_device, repeat, set_evdev_hooks,
    set_repeat, unpublish_evdev, CapBitmap, EvdevHooks, VirtioInputDev,
};
pub use types::{InputEvent, VirtioInputAbsInfo, VirtioInputDevIds, VirtioInputEvent};
pub use virtio::VirtioChildDeviceKey;

pub const MAX_INPUT_DEVICES: usize = 8;
/// Red Hat virtio PCI vendor ID used by the synthetic virtio-input model.
pub use virtio::resources::VIRTIO_VENDOR_ID as VIRTIO_PCI_VENDOR_ID;
pub const DEFAULT_REPEAT: [u32; 2] = [250, 33];

#[cfg(test)]
mod tests;
