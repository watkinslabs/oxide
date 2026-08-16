//! `/sys/power` registration per `32a§11`.
//!
//! Every decision (labels, write semantics, errno mapping) lives in the
//! `power` crate's `suspend::sysfs_api` — ungated and host-tested. This file
//! only registers names and forwards bytes; adding an attribute here without
//! it existing in `power::suspend::sysfs_api::ATTRS`/`STATS_ATTRS` is not
//! possible because both registration loops are driven from those constants.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{KResult, VfsError};

use power::suspend::sysfs_api;

use crate::kobject::{make_attr_inode, Attribute, SysfsOps};
use crate::{register, RO_PERM, RW_PERM};

/// Map a `power::Error` onto the `VfsError` a syscall returns.
///
/// Total over `power::decide::Error`'s ten variants — a new variant added
/// there without a corresponding arm here is a compile error, not a silent
/// `Einval` default. `Again`/`Nomem` have no closer VFS analogue than their
/// own-named `Eagain`/`Enomem`.
/// # C: O(1)
fn map_err(e: power::Error) -> VfsError {
    match e {
        power::Error::Inval  => VfsError::Einval,
        power::Error::Perm   => VfsError::Eperm,
        power::Error::Io     => VfsError::Eio,
        power::Error::Busy   => VfsError::Ebusy,
        power::Error::Nosys  => VfsError::Enosys,
        power::Error::Opnotsupp => VfsError::Eopnotsupp,
        power::Error::Again  => VfsError::Eagain,
        power::Error::Intr   => VfsError::Eintr,
        power::Error::Nomem  => VfsError::Enomem,
        power::Error::Nodata => VfsError::Enodata,
    }
}

/// `SysfsOps` for the six `/sys/power/*` attributes: forwards to
/// `sysfs_api::show`/`store`.
struct PowerOps;
impl SysfsOps for PowerOps {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        sysfs_api::show(attr).map_err(map_err)
    }
    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        sysfs_api::store(attr, buf).map_err(map_err)?;
        Ok(buf.len())
    }
}

/// `SysfsOps` for the read-only `/sys/power/suspend_stats/*` attributes:
/// forwards to `sysfs_api::show_stat`; `store` stays the `SysfsOps` default
/// (`Erofs`).
struct StatsOps;
impl SysfsOps for StatsOps {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        sysfs_api::show_stat(attr).map_err(map_err)
    }
}

/// Ino base for `/sys/power/*` (`ids.rs` block convention, step 0x0001_0000).
const POWER_ATTR_BASE: u64 = crate::ids::POWER_ATTR_BASE;
/// Ino base for `/sys/power/suspend_stats/*`, one block over.
const POWER_STATS_ATTR_BASE: u64 = crate::ids::POWER_STATS_ATTR_BASE;

/// Register `/sys/power` and `/sys/power/suspend_stats`.
///
/// Driven from `sysfs_api::ATTRS`/`STATS_ATTRS` by index, so an attribute
/// added to the power crate cannot leave a sysfs file unregistered: the loop
/// bound is the constant's length, not a hand-maintained list here.
/// # C: O(N_attrs + N_stats)
pub fn init() {
    let ops: Arc<dyn SysfsOps> = Arc::new(PowerOps);
    for (i, a) in sysfs_api::ATTRS.iter().enumerate() {
        let mode = if a.writable { RW_PERM } else { RO_PERM };
        let attr = Attribute { name: a.name, mode };
        let ino = POWER_ATTR_BASE + i as u64;
        let path = alloc::format!("/sys/power/{}", a.name);
        register(&path, make_attr_inode(&attr, Arc::clone(&ops), ino));
    }
    let stats_ops: Arc<dyn SysfsOps> = Arc::new(StatsOps);
    for (i, name) in sysfs_api::STATS_ATTRS.iter().enumerate() {
        let attr = Attribute { name, mode: RO_PERM };
        let ino = POWER_STATS_ATTR_BASE + i as u64;
        let path = alloc::format!("/sys/power/suspend_stats/{}", name);
        register(&path, make_attr_inode(&attr, Arc::clone(&stats_ops), ino));
    }
}

#[cfg(test)]
#[path = "power/tests.rs"]
mod tests;
