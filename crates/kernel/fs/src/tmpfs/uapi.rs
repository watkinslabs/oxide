/// TMPFS_MAGIC (linux/magic.h) — statfs `f_type`.
pub(super) const TMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;
/// RAMFS_MAGIC (linux/magic.h). ramfs reuses tmpfs's in-memory tree here but is
/// a DISTINCT filesystem type to userspace: it reports its own `f_type` and its
/// own `/proc/mounts` name, exactly as Linux `ramfs_fill_super` does. Reporting
/// TMPFS_MAGIC for a ramfs mount breaks every `statfs`-based fs probe.
pub const RAMFS_MAGIC: u64 = 0x8584_58f6;
/// Fallback `fsid` for an anonymous inode (memfd / coredump) with no owning
/// SuperBlock; tree inodes derive `fsid` from `i_sb().s_dev`.
pub(super) const TMPFS_FSID: u64 = 0x0102_1994;
