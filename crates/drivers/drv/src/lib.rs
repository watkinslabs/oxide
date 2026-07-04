// Authoritative driver model per `35`: bus/device/driver registries,
// probe/remove binding, sysfs hooks, and devtmpfs publication hooks.
// `drv::init()` reports the core ready; real probing happens through
// `register_driver` and fallible `try_device_add` attachment.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod model;
pub use model::{
    bind, BindEvent, Device, Driver, NodeFactory, Resource, register_driver, unregister_driver, devices, device_count,
    try_device_add, device_del, driver_names, driver_names_for_bus, driver_count, match_driver, bind_addr, unbind,
    shutdown_all, set_sysfs_hook, set_sysfs_remove_hook, set_bind_hook, set_driver_hook, set_devtmpfs_hook,
    set_devtmpfs_del_hook,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NoMatch, NoMem, ProbeFailed, Removed, AlreadyBound, NotFound, Busy }

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time init reporter. Per-driver `register_driver()` calls happen from
/// kernel boot before bus enumeration starts binding devices.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_ok() {
        // SAFETY: hosted-test path; init has no side effects + no preconditions on host.
        unsafe { assert!(init().is_ok()); }
    }
}
