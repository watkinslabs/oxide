#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod consts;
mod registry;
mod types;

pub use consts::*;
pub use registry::{
    install_device, Error, KResult,
};
pub use input::{
    count, device, devices_snapshot, evdev_id_for_device, install, is_pointer, name_of,
    remove_device, repeat, set_repeat, CapBitmap, VirtioInputDev,
};
#[cfg(any(target_os = "oxide-kernel", test))]
pub use registry::{install_device_with_parent, remove_device_with_node, ModelParent};
pub use types::{InputEvent, VirtioInputAbsInfo, VirtioInputDevIds, VirtioInputEvent};

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod procfs;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod devfs;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod drain;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod evdev_queue;

pub mod keymap;

#[cfg(test)]
mod tests;
