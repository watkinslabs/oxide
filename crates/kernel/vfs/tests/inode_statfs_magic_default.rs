//! ledger D33 (inode/statfs-on-inode-not-super, inode-side REMAINS):
//! `super_operations->statfs` is the primary `statfs(2)` path now, but the
//! inode-level `Inode::statfs_magic()` SURVIVES for genuinely anonymous /
//! pathless descriptors (pidfd, anon_inode families) that have no mount to
//! resolve a magic from — which is correct Linux behaviour (`fstatfs` on such
//! an fd reports the inode's own pseudo-fs magic). This locks that surface:
//!   * the default is `0` = "no inode-supplied magic, use the path/mount
//!     fallback" (a real superblock-backed inode never overrides it);
//!   * an anonymous inode overrides it with its pseudo-fs magic so `fstatfs`
//!     has a stable `f_type` with no pathname.
//! Pure-trait fixtures, no global state, no QEMU.

use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Linux `PROC_SUPER_MAGIC` (`include/uapi/linux/magic.h`) — a representative
/// anon/pseudo-fs magic value; the exact number is not load-bearing here, only
/// that the override is reported verbatim.
const ANON_MAGIC: u64 = 0x9fa0;

/// Mount-backed inode: no `statfs_magic` override → default `0`, so `fstatfs`
/// falls through to the mount/superblock magic.
struct PathBacked;
impl Inode for PathBacked {
    fn ino(&self) -> vfs::Ino { 2 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Anonymous/pathless descriptor inode (pidfd shape): supplies its own magic
/// because there is no mount to derive one from.
struct AnonFd;
impl Inode for AnonFd {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn statfs_magic(&self) -> u64 { ANON_MAGIC }
}

#[test]
fn default_statfs_magic_is_zero_fallthrough() {
    // A normal inode supplies no magic → `0` means "use the path/mount magic".
    assert_eq!(PathBacked.statfs_magic(), 0);
}

#[test]
fn anon_inode_supplies_own_magic() {
    // A pathless fd reports its pseudo-fs magic directly, with no mount lookup.
    assert_eq!(AnonFd.statfs_magic(), ANON_MAGIC);
    assert_ne!(AnonFd.statfs_magic(), 0, "anon magic must not collapse to the fallthrough sentinel");
}
