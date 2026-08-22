// `xtask image`, `xtask grub` per `07§8`.
//
// This is a manifest. The shared boot cmdline, shared path/QEMU helpers,
// serial-log placement, command dispatch, aarch64 GRUB booting, and x86_64
// GRUB booting live in separate modules.

mod aarch64;
mod bootargs;
mod commands;
mod common;
mod serial_log;
mod x86_64;

pub(crate) use aarch64::build_arm_image;
pub(crate) use commands::{cmd_grub, cmd_image};
pub(crate) use common::repo_root;

/// Linux device name for the UART QEMU wires on `arch`. Every path-valued
/// image parameter and injected service must follow the same identity as the
/// kernel's serial devnode. # C: O(1)
pub(crate) fn serial_device_name(arch: &str) -> &'static str {
    if arch == "aarch64" { "ttyAMA0" } else { "ttyS0" }
}
