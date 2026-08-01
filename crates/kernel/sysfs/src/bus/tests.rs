//! Bus/sysfs test manifest.
//!
//! Test ownership:
//! - `block_index`: block-registry `/sys/dev/block` projection.
//! - `device_index`: character indexes, device attributes, and parent topology.
//! - `driver_binding`: driver bind/unbind and lifecycle behavior.
//! - `pci_dev_attrs`: the PCI function attribute directory userspace reads.
//! - `uevent_replay`: replayed device uevents and nested paths.

extern crate alloc;

mod block_index;
mod device_index;
mod driver_binding;
mod pci_dev_attrs;
mod topology_liveness;
mod uevent_replay;

use super::dirs::{make_bus_devices_inode, make_bus_drivers_inode, make_devices_root_inode};
use super::hooks::*;
use super::index::{dev_devpath, make_sys_dev_index_inode, DevIndexKind};
use super::device_hook_serial;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use driver_binding::{next_uevent_matching, uevent_has_entry};
use vfs::VfsError;
