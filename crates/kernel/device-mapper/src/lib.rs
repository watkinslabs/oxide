#![no_std]

//! Device-mapper module manifest.
//!
//! - `uapi`: command numbers and wire layouts.
//! - `target`: the mapping-target contract.
//! - `types`: target-type registry.
//! - `table`: constructed mapping tables and lookup.
//! - `device`: mapped-device state and block I/O.

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod args;
pub mod control;
pub mod defer;
pub mod devt;
pub mod device;
pub mod split;
pub mod suspend;
pub mod table;
pub mod target;
pub mod targets;
pub mod types;
pub mod uapi;

/// Publish the mapper control node and install the built-in target types.
/// Kernel boot calls this after devfs installed its device-model hooks; the
/// operation is idempotent for staged initialization and hosted tests.
/// # C: O(built-in targets + device registration)
pub fn init() -> crate::target::DmResult<()> {
    types::register_builtin();
    let devt = vfs::Devt::new(10, uapi::MISC_MAPPER_CONTROL_MINOR);
    if vfs::lookup_chrdev(devt).is_none() {
        vfs::register_chrdev_region(10, uapi::MISC_MAPPER_CONTROL_MINOR, 1,
            alloc::sync::Arc::new(control::ControlCharOps))
            .map_err(|_| syscall::errno::Errno::Ebusy)?;
    }
    let node_name = alloc::format!("{}/{}", uapi::DM_DIR, uapi::DM_CONTROL_NODE);
    match drv::try_device_add(alloc::sync::Arc::new(
        drv::Device::new("misc", "device-mapper-control".into(), 0, 0, 0)
            .with_devnode("misc", node_name, Some((10, uapi::MISC_MAPPER_CONTROL_MINOR))))) {
        Ok(_) => Ok(()),
        Err(drv::Error::Busy) if drv::devices().iter().any(|dev| {
            dev.bus == "misc"
                && dev.addr == "device-mapper-control"
                && dev.dev_class == "misc"
                && dev.devname.as_deref() == Some("mapper/control")
                && dev.dev_t == Some((10, uapi::MISC_MAPPER_CONTROL_MINOR))
        }) => Ok(()),
        Err(_) => Err(syscall::errno::Errno::Ebusy),
    }
}
