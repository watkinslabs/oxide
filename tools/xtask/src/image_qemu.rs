// `xtask image`, `xtask grub` per `07§8`.
//
// This is a manifest. Shared path/QEMU helpers, command dispatch, aarch64 GRUB
// booting, and x86_64 GRUB booting live in separate modules.

mod aarch64;
mod commands;
mod common;
mod x86_64;

pub(crate) use aarch64::build_arm_image;
pub(crate) use commands::{cmd_grub, cmd_image};
pub(crate) use common::repo_root;
