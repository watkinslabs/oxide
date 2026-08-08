// Filesystem-type registration for hugetlbfs.
//
// Kept here rather than in the mount registry so the whole of this filesystem
// — its options, its constructor, and the flags it presents — lives in one
// subtree, and the registry's only involvement is naming it once.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;

use vfs::fs::{register_fs, superblock_from_filesystem, FsFlags, FsParameter, FsType};
use vfs::superblock::SuperBlock;
use vfs::KResult;

use super::fs::HugetlbfsFs;
use super::params::HUGETLBFS_PARAMS;
use super::uapi::HUGETLBFS_MAGIC;

/// `hugetlbfs_get_tree` — one instance per mount, sized by that mount's own
/// options.
/// # C: O(len(data)) + O(min_size pages)
fn ctor(ty: Arc<dyn vfs::FileSystemType>, _src: Option<&str>, target: &str, data: &str,
        sb_flags: u64, _params: &[FsParameter]) -> KResult<Arc<SuperBlock>> {
    let hfs = HugetlbfsFs::from_mount_data(data)?;
    let root = hfs.root_inode();
    let fs: Arc<dyn vfs::fs::FileSystem> = hfs;
    superblock_from_filesystem(ty, fs, Some(root), target.to_string(), sb_flags)
}

/// Publish `hugetlbfs` as a mountable filesystem type.
///
/// `FS_ALLOW_IDMAP` and NOT `FS_USERNS_MOUNT`: a mount reserves pages from a
/// global pool, so an unprivileged user namespace may not create one.
/// # C: O(1)
pub fn register() -> KResult<()> {
    register_fs(FsType::with_parameters(
        "hugetlbfs", HUGETLBFS_MAGIC, FsFlags::FS_ALLOW_IDMAP,
        Box::new(ctor), Some(HUGETLBFS_PARAMS),
    ))
}
