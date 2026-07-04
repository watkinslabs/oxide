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
        const FS_RENAME_DOES_D_MOVE   = 32768;
    }
}
