// Hosted devfs test manifest.
//
// Module manifest:
// - `hotplug`: hot-unplug/rebind path resolution through a real devtmpfs mount.
// - `fileattr`: `file_getattr(2)`/`file_setattr(2)` + `FS_IOC_FSGETXATTR` over
//   `/dev` directories vs device nodes.

mod fileattr;
mod hotplug;

/// The devfs tree, the driver registry, and the devtmpfs hooks are kernel-wide
/// singletons no test can own; every test that mutates them takes this first.
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
