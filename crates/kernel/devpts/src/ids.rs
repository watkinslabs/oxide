//! Synthetic devpts inode and device identities.
pub(crate) const PTMX_ROOT_INO: u64 = 0x6000_FFFF;
pub(crate) const PTMX_MOUNT_INO: u64 = 0x6000_FFFE;
pub(crate) const PTMX_RDEV: u32 = 0x0502;
