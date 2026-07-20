//! Dynamic sysfs bus/device tree.
//!
//! Module manifest:
//! - `ids`: inode ranges and bus root/name mapping helpers.
//! - `device`: device kobject attributes and canonical device directories.
//! - `index`: `/sys/dev/{char,block}` reverse dev_t indexes.
//! - `dirs`: `/sys/devices/*` and `/sys/bus/*/{devices,drivers}` directories.
//! - `driver`: driver directories plus bind/unbind attributes.
//! - `hooks`: driver-model init and uevent callbacks.
//! - `tests`: sysfs bus/device model tests.

mod device;
mod dirs;
mod driver;
mod hooks;
mod ids;
mod index;
#[cfg(test)]
mod test_harness;

pub(crate) use device::{dev_canon, ups_prefix};
pub use hooks::{bind_device_cb, init, publish_device_cb, publish_driver_cb, remove_device_cb};
#[cfg(test)]
pub(crate) use test_harness::device_hook_serial;

#[cfg(test)]
mod tests;
