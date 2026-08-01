// ext4 mount-option contract constants: the quota-family option tokens, the
// per-superblock quota mount-opt bits those tokens set/clear, and the
// `jqfmt=` enum names. Contract-owned; no policy or parsing here.

/// Any quota accounting requested (`quota`/`usrquota`/`grpquota`/`prjquota`,
/// or a journalled quota file name applied at mount).
pub const EXT4_MOUNT_QUOTA: u32 = 1 << 0;
/// User-quota LIMIT enforcement requested.
pub const EXT4_MOUNT_USRQUOTA: u32 = 1 << 1;
/// Group-quota LIMIT enforcement requested.
pub const EXT4_MOUNT_GRPQUOTA: u32 = 1 << 2;
/// Project-quota LIMIT enforcement requested.
pub const EXT4_MOUNT_PRJQUOTA: u32 = 1 << 3;

/// Every quota mount-opt bit — the set `noquota` clears and the set a
/// quota-loaded remount refuses to empty.
pub const EXT4_MOUNT_QUOTA_MASK: u32 =
    EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA | EXT4_MOUNT_GRPQUOTA | EXT4_MOUNT_PRJQUOTA;

pub const OPT_QUOTA:     &str = "quota";
pub const OPT_NOQUOTA:   &str = "noquota";
pub const OPT_USRQUOTA:  &str = "usrquota";
pub const OPT_GRPQUOTA:  &str = "grpquota";
pub const OPT_PRJQUOTA:  &str = "prjquota";
pub const OPT_USRJQUOTA: &str = "usrjquota";
pub const OPT_GRPJQUOTA: &str = "grpjquota";
pub const OPT_JQFMT:     &str = "jqfmt";

pub const JQFMT_NAME_VFSOLD: &str = "vfsold";
pub const JQFMT_NAME_VFSV0:  &str = "vfsv0";
pub const JQFMT_NAME_VFSV1:  &str = "vfsv1";

/// Separator between mount-data options.
pub const OPT_SEP: char = ',';
/// Separator between an option key and its value.
pub const OPT_ASSIGN: char = '=';
/// A journalled quota file name must live in the filesystem root, so it may
/// carry no path separator.
pub const PATH_SEP: char = '/';

/// `jqfmt=` value → on-disk quota format id; `None` for an unknown name.
/// # C: O(1)
pub fn jqfmt_from_name(name: &str) -> Option<u32> {
    match name {
        JQFMT_NAME_VFSOLD => Some(vfs::QFMT_VFS_OLD),
        JQFMT_NAME_VFSV0  => Some(vfs::QFMT_VFS_V0),
        JQFMT_NAME_VFSV1  => Some(vfs::QFMT_VFS_V1),
        _ => None,
    }
}

/// Quota format id → the `jqfmt=` name `/proc/mounts` shows; `None` when no
/// journalled quota format is selected.
/// # C: O(1)
pub fn jqfmt_name(fmt: u32) -> Option<&'static str> {
    match fmt {
        vfs::QFMT_VFS_OLD => Some(JQFMT_NAME_VFSOLD),
        vfs::QFMT_VFS_V0  => Some(JQFMT_NAME_VFSV0),
        vfs::QFMT_VFS_V1  => Some(JQFMT_NAME_VFSV1),
        _ => None,
    }
}

/// Limit-enforcement mount-opt bit for one quota class.
/// # C: O(1)
pub fn limit_bit(kind: vfs::QuotaType) -> u32 {
    match kind {
        vfs::QuotaType::User    => EXT4_MOUNT_USRQUOTA,
        vfs::QuotaType::Group   => EXT4_MOUNT_GRPQUOTA,
        vfs::QuotaType::Project => EXT4_MOUNT_PRJQUOTA,
    }
}
