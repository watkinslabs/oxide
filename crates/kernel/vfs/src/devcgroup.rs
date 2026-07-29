// `include/linux/device_cgroup.h` — `devcgroup_inode_permission()` and
// `devcgroup_inode_mknod()`, the two points at which the VFS consults the
// device controller. Linux compiles them to `return 0` without
// `CONFIG_CGROUP_DEVICE`/`CONFIG_CGROUP_BPF`; here the same "off" state
// is an uninstalled hook.
//
// The decision itself belongs to the BPF cgroup program array in
// `security::bpf::devcg`, which cannot be called directly: `security`
// depends on `vfs`. The hook is installed once at boot, the same shape
// `RLIMIT_FSIZE` uses in `setattr.rs`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::devnode::Devt;
use crate::inode::Inode;
use crate::types::{FileType, KResult};
use crate::namei::{MAY_READ, MAY_WRITE};

/// `devcgroup_check_permission(type, major, minor, access)` — `type` is
/// one of `DEVCG_DEV_BLOCK`/`DEVCG_DEV_CHAR`, `access` a mask of
/// `DEVCG_ACC_MKNOD`/`READ`/`WRITE`.
pub type DevCgroupHook = fn(u16, u32, u32, u16) -> KResult<()>;

/// `DEVCG_ACC_MKNOD`.
pub const DEVCG_ACC_MKNOD: u16 = 1;
/// `DEVCG_ACC_READ`.
pub const DEVCG_ACC_READ:  u16 = 2;
/// `DEVCG_ACC_WRITE`.
pub const DEVCG_ACC_WRITE: u16 = 4;
/// `DEVCG_DEV_BLOCK`.
pub const DEVCG_DEV_BLOCK: u16 = 1;
/// `DEVCG_DEV_CHAR`.
pub const DEVCG_DEV_CHAR:  u16 = 2;

/// `WHITEOUT_DEV` (`include/linux/fs.h`) — `MKDEV(0, 0)`, an overlayfs
/// whiteout rather than a device, exempt from the mknod check.
const WHITEOUT_DEV: u32 = 0;

static HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the device-controller decision. Boot path. # C: O(1)
pub fn set_devcgroup_hook(f: DevCgroupHook) { HOOK.store(f as usize as u64, Ordering::Release); }

/// Drop the installed decision (hosted tests). # C: O(1)
pub fn clear_devcgroup_hook() { HOOK.store(0, Ordering::Release); }

/// # C: O(1)
fn hook() -> Option<DevCgroupHook> {
    let raw = HOOK.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `set_devcgroup_hook` is the only writer and stores only a
    // `DevCgroupHook` fn pointer, so this transmute restores its own type.
    Some(unsafe { core::mem::transmute::<usize, DevCgroupHook>(raw as usize) })
}

/// `devcgroup_check_permission()`. # C: O(hook)
pub fn devcgroup_check_permission(dev_type: u16, major: u32, minor: u32, access: u16) -> KResult<()> {
    match hook() { Some(f) => f(dev_type, major, minor, access), None => Ok(()) }
}

/// `devcgroup_inode_permission()` — a non-device inode, or a device node
/// with no `i_rdev`, never reaches the controller. # C: O(hook)
pub fn devcgroup_inode_permission(inode: &Inode, mask: u32) -> KResult<()> {
    let dev_type = match inode.file_type() {
        FileType::BlockDev => DEVCG_DEV_BLOCK,
        FileType::CharDev  => DEVCG_DEV_CHAR,
        _ => return Ok(()),
    };
    let rdev = inode.rdev();
    if rdev == 0 { return Ok(()); }
    let mut access = 0u16;
    if mask & MAY_WRITE != 0 { access |= DEVCG_ACC_WRITE; }
    if mask & MAY_READ != 0 { access |= DEVCG_ACC_READ; }
    let d = Devt::from_raw(rdev);
    devcgroup_check_permission(dev_type, d.major(), d.minor(), access)
}

/// `devcgroup_inode_mknod()` — `mode` is the full `S_IF*`-bearing mode
/// and `dev` the packed `dev_t` `mknod(2)` was handed. # C: O(hook)
pub fn devcgroup_inode_mknod(file_type: FileType, dev: u32) -> KResult<()> {
    let dev_type = match file_type {
        FileType::BlockDev => DEVCG_DEV_BLOCK,
        FileType::CharDev if dev != WHITEOUT_DEV => DEVCG_DEV_CHAR,
        _ => return Ok(()),
    };
    let d = Devt::from_raw(dev);
    devcgroup_check_permission(dev_type, d.major(), d.minor(), DEVCG_ACC_MKNOD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static SEEN: AtomicU32 = AtomicU32::new(0);

    fn record(dev_type: u16, major: u32, minor: u32, access: u16) -> KResult<()> {
        SEEN.store(((dev_type as u32) << 24) | (major << 16) | (minor << 8) | access as u32,
                   Ordering::Release);
        Err(crate::types::VfsError::Eperm)
    }

    /// One test: the hook is process-global, so splitting these would let
    /// the crate's parallel test threads clobber each other's install.
    #[test]
    fn the_mknod_classifier_matches_devcgroup_inode_mknod() {
        clear_devcgroup_hook();
        // Off (no hook) is Linux's `CONFIG_CGROUP_DEVICE=n` stub: allow.
        assert_eq!(devcgroup_inode_mknod(FileType::CharDev, Devt::new(1, 3).raw()), Ok(()));
        assert_eq!(devcgroup_check_permission(DEVCG_DEV_CHAR, 1, 3, DEVCG_ACC_READ), Ok(()));

        set_devcgroup_hook(record);
        SEEN.store(0, Ordering::Release);
        // A whiteout char device is not a device.
        assert_eq!(devcgroup_inode_mknod(FileType::CharDev, WHITEOUT_DEV), Ok(()));
        // Neither is anything that is not a device node.
        assert_eq!(devcgroup_inode_mknod(FileType::Regular, 0), Ok(()));
        assert_eq!(devcgroup_inode_mknod(FileType::Fifo, 0), Ok(()));
        assert_eq!(SEEN.load(Ordering::Acquire), 0);

        assert!(devcgroup_inode_mknod(FileType::BlockDev, Devt::new(8, 2).raw()).is_err());
        let seen = SEEN.load(Ordering::Acquire);
        assert_eq!(seen >> 24, DEVCG_DEV_BLOCK as u32);
        assert_eq!((seen >> 16) & 0xff, 8);
        assert_eq!((seen >> 8) & 0xff, 2);
        assert_eq!(seen & 0xff, DEVCG_ACC_MKNOD as u32);
        clear_devcgroup_hook();
    }
}
