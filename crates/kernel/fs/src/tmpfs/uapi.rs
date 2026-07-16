/// TMPFS_MAGIC (linux/magic.h) — statfs `f_type`.
pub(super) const TMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;
/// Fallback `fsid` for an anonymous inode (memfd / coredump) with no owning
/// SuperBlock; tree inodes derive `fsid` from `i_sb().s_dev`.
pub(super) const TMPFS_FSID: u64 = 0x0102_1994;
