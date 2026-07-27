bitflags::bitflags! {
    /// `file_system_type::fs_flags` (Linux `include/linux/fs.h`).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct FsFlags: u32 {
        const FS_REQUIRES_DEV         = 1;
        const FS_BINARY_MOUNTDATA     = 2;
        const FS_HAS_SUBTYPE          = 4;
        const FS_USERNS_MOUNT         = 8;
        const FS_DISALLOW_NOTIFY_PERM = 16;
        const FS_ALLOW_IDMAP          = 32;
        /// `FS_USERNS_MOUNT_RESTRICTED` — "restrict mount in userns if not
        /// already visible". Carried by procfs and sysfs, and the flag
        /// `acct(2)` tests to refuse accounting to a pseudo filesystem
        /// (`kernel/acct.c acct_on`).
        const FS_USERNS_MOUNT_RESTRICTED = 512;
        const FS_RENAME_DOES_D_MOVE   = 32768;
    }
}
