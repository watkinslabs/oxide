use alloc::sync::Weak;

use core::sync::atomic::Ordering;

use vfs::{Ino, InodeRef};
use vfs::superblock::SuperBlock;

use super::limits::NEXT_INO;
use super::uapi::HUGETLBFS_FSID;

/// `fsid` from an inode's owning SB, else this filesystem's fallback for a
/// file on a kernel-private mount. # C: O(1)
pub(super) fn fsid_of(sb: &Weak<SuperBlock>) -> u64 {
    sb.upgrade().map(|s| s.s_dev).unwrap_or(HUGETLBFS_FSID)
}

/// Next inode number from this filesystem's own band. # C: O(1)
pub(super) fn next_ino() -> Ino { NEXT_INO.fetch_add(1, Ordering::Relaxed) }

/// Route a freshly-built inode through the owning SB's inode cache so a later
/// lookup of the same number returns the SAME `Arc`. A file on a mount with no
/// superblock (the kernel-private mount) has no cache to register in.
/// # C: O(log N_ino)
pub(super) fn iget_or_build(sb: &Weak<SuperBlock>, ino: Ino, build: impl FnOnce() -> InodeRef) -> InodeRef {
    match sb.upgrade() { Some(s) => s.iget(ino, build), None => build() }
}
