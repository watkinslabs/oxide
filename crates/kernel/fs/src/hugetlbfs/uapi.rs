/// HUGETLBFS_MAGIC — statfs `f_type`.
pub const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;

/// Fallback `fsid` for a file on a kernel-private mount that carries no
/// SuperBlock; tree inodes derive `fsid` from `i_sb().s_dev`.
pub(super) const HUGETLBFS_FSID: u64 = 0x0958_4586;
