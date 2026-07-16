//! Synthetic devpts inode and device identities.
pub(crate) const PTMX_ROOT_INO: u64 = 0x6000_FFFF;
pub(crate) const PTMX_MOUNT_INO: u64 = 0x6000_FFFE;
pub(crate) const PTMX_RDEV: u32 = 0x0502;
pub(crate) const PTY_MASTER_INO_BASE: u64 = 0x6000_0000;
pub(crate) const PTY_SLAVE_INO_BASE: u64 = 0x6000_8000;
pub(crate) const PTY_MASTER_RDEV_BASE: u32 = 0x8000;
pub(crate) const PTY_SLAVE_RDEV_BASE: u32 = 0x8800;
