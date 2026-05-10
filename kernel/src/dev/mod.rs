//! Kernel-side `/dev/*` device producers per `52§3` integration layer.
//!
//! Submodules wrap a domain crate or driver and register the
//! resulting `vfs::Inode` into `devfs`. Boot bootstrap in
//! `kernel::devfs::init` calls each module's `init()` once.

#![cfg(target_os = "oxide-kernel")]

pub mod console;
pub mod drm;
pub mod pidfd;
pub mod pty;
pub mod tracefs;
