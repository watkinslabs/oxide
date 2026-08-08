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
