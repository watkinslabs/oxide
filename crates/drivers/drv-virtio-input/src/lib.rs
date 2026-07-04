#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod consts;
mod registry;
mod types;

pub use consts::*;
pub use registry::{
    count, device, devices_snapshot, evdev_id_for_device, install, install_device, is_pointer,
    name_of, remove_device, repeat, set_repeat, CapBitmap, Error, KResult, VirtioInputDev,
};
pub use types::{InputEvent, VirtioInputAbsInfo, VirtioInputDevIds, VirtioInputEvent};

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod procfs;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod devfs;

#[cfg(target_os = "oxide-kernel")]
pub mod drain;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod evdev_queue;

pub mod keymap;

#[cfg(test)]
mod tests;
