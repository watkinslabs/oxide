#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
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
