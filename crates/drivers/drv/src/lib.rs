// Module manifest:
// - `model`: device/driver registries, lifecycle, binding, publication hooks.
// - `path`: exact ancestry and canonical live-object paths.
// - `pci_dev`: PCI-function identity + config-space/rescan indirection.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod model;
pub mod pci_dev;
mod path;
pub use pci_dev::{
    pci_config_read, pci_config_write, pci_rescan, set_pci_config_hooks, set_pci_rescan_hook,
    PciIdent,
};
pub use path::{
    device_canon, device_canon_exact, device_parent_canon_exact, device_root_canon,
};
pub use model::{
    bind, BindEvent, Device, Driver, NodeFactory, Resource, IORESOURCE_IO, IORESOURCE_MEM,
    NUMA_NODE_NONE, PCI_DEFAULT_DMA_MASK,
    IORESOURCE_PREFETCH,
    register_driver, unregister_driver, devices, device_count, find_matching_device_identity,
    try_device_add, try_device_add_with_parent, device_del, rollback_devices, driver_names,
    driver_names_for_bus, driver_count, match_driver, bind_addr, unbind,
    shutdown_all, set_sysfs_hook, set_sysfs_remove_hook, set_bind_hook, set_driver_hook, set_devtmpfs_hook,
    set_devtmpfs_del_hook,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NoMatch, NoMem, ProbeFailed, Removed, AlreadyBound, NotFound, Busy, Invalid }

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
