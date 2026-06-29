//! ledger D33 (inode/statfs-on-inode-not-super, inode-side REMAINS):
//! `super_operations->statfs` is the primary `statfs(2)` path now, but the
//! inode-level `Inode::statfs_magic()` SURVIVES for genuinely anonymous /
//! pathless descriptors (pidfd, anon_inode families) that have no mount to
//! resolve a magic from — which is correct Linux behaviour (`fstatfs` on such
//! an fd reports the inode's own pseudo-fs magic). This locks that surface:
//!   * the default is `0` = "no inode-supplied magic, use the path/mount
//!     fallback" (an inode with no owning superblock);
//!   * an anonymous inode whose owning superblock carries the pseudo-fs magic
//!     reports it verbatim so `fstatfs` has a stable `f_type` with no pathname.
//! Pure fixtures, no global state, no QEMU.
//!
//! Migration note (B280b): `statfs_magic()` is no longer a per-inode trait
//! override; the concrete `Inode` derives it from `i_sb().s_magic`. The same
//! assertions hold — the anon magic is now carried by the inode's superblock.

use std::sync::Arc;

use vfs::inode::InodeBuilder;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, KResult};

/// Linux `PROC_SUPER_MAGIC` (`include/uapi/linux/magic.h`) — a representative
/// anon/pseudo-fs magic value; the exact number is not load-bearing here, only
/// that the override is reported verbatim.
const ANON_MAGIC: u64 = 0x9fa0;

struct NullType;
impl FileSystemType for NullType {
    fn name(&self) -> &str { "t" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { unreachable!() }
}
struct NullOps;
impl SuperOps for NullOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb(magic: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(NullType), Arc::new(NullOps), magic, 0x10, 4096, "t".into(), Arc::new(()))
}

/// Mount-backed inode: no owning superblock → default `0`, so `fstatfs`
/// falls through to the mount/superblock magic.
fn path_backed() -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Anonymous/pathless descriptor inode (pidfd shape): supplies its own magic
/// via the owning pseudo-fs superblock.
fn anon_fd(sb: &Arc<SuperBlock>) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}

#[test]
fn default_statfs_magic_is_zero_fallthrough() {
    // A normal inode supplies no magic → `0` means "use the path/mount magic".
    assert_eq!(path_backed().statfs_magic(), 0);
}

#[test]
fn anon_inode_supplies_own_magic() {
    // A pathless fd reports its pseudo-fs magic directly, with no mount lookup.
    let s = sb(ANON_MAGIC);
    let node = anon_fd(&s);
    assert_eq!(node.statfs_magic(), ANON_MAGIC);
    assert_ne!(node.statfs_magic(), 0, "anon magic must not collapse to the fallthrough sentinel");
}
