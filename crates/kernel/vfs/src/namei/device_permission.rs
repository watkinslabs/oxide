//! Central device-open gates: resolved-mount nodev policy plus device security.

use sync::{Inode as InodeLockClass, Spinlock};

use crate::{FileType, KResult};

fn may_open_dev_flags(mnt_flags: u64, sb_iflags: u64) -> bool {
    mnt_flags & crate::mount::MNT_NODEV == 0
        && sb_iflags & crate::superblock::SB_I_NODEV == 0
}

/// Linux `may_open_dev` for a resolved path's exact mount identity.
///
/// `mnt_id` must come from `VfsPath.mnt_id`; retaining the per-mount identity
/// is what distinguishes a nodev bind mount from another mount of the same
/// superblock. Missing/detached identities fail closed.
/// # C: O(log mounts)
pub fn may_open_dev(mnt_id: u64) -> bool {
    let Some(mnt) = crate::mount::mount_by_id(mnt_id) else { return false };
    may_open_dev_flags(mnt.flags(), mnt.sb().s_iflags())
}

/// Security policy over a device type, encoded dev_t, and MAY_* mask.
pub type DevicePermissionHook = fn(FileType, u32, u32) -> KResult<()>;

static DEVICE_PERMISSION_HOOK: Spinlock<Option<DevicePermissionHook>, InodeLockClass> =
    Spinlock::new(None);

/// Install the kernel security device-policy hook. # C: O(1)
pub fn set_device_permission_hook(hook: DevicePermissionHook) {
    *DEVICE_PERMISSION_HOOK.lock() = Some(hook);
}

/// Apply canonical device policy to a char/block device identity.
///
/// A zero rdev without a registered cdev/bdev is an internal pseudo inode,
/// matching Linux's early `!inode->i_cdev && !inode->i_bdev` return.
/// # C: O(policy)
pub fn device_permission(file_type: FileType, rdev: u32, mask: u32) -> KResult<()> {
    if rdev == 0 || !matches!(file_type, FileType::CharDev | FileType::BlockDev) {
        return Ok(());
    }
    let hook = *DEVICE_PERMISSION_HOOK.lock();
    match hook { Some(check) => check(file_type, rdev, mask), None => Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::may_open_dev_flags;

    #[test]
    fn may_open_dev_uses_mount_nodev_and_internal_sb_nodev_only() {
        assert!(may_open_dev_flags(0, 0));
        assert!(!may_open_dev_flags(crate::mount::MNT_NODEV, 0));
        assert!(!may_open_dev_flags(0, crate::superblock::SB_I_NODEV));
        assert!(!may_open_dev_flags(
            crate::mount::MNT_NODEV,
            crate::superblock::SB_I_NODEV,
        ));
    }
}
