// Hosted devfs test manifest.
//
// Module manifest:
// - `hotplug`: hot-unplug/rebind path resolution through a real devtmpfs mount.

mod hotplug;

/// The devfs tree, the driver registry, and the devtmpfs hooks are kernel-wide
/// singletons no test can own; every test that mutates them takes this first.
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
