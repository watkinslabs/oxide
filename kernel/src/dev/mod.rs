//! Kernel-side `/dev/*` device producers per `52§3` integration layer.
//!
//! Submodules wrap a domain crate or driver and register the
//! resulting `vfs::Inode` into `devfs`. Boot bootstrap in
//! `kernel::devfs::init` calls each module's `init()` once.

#![cfg(target_os = "oxide-kernel")]

// console char device (/dev/console,/dev/tty[N]) → `console` crate (docs/53)
pub use console;
pub mod drm;
pub mod pidfd;
// pty (/dev/ptmx,/dev/pts) → `devpts` crate (docs/53)
pub use devpts as pty;
pub mod tracefs;
