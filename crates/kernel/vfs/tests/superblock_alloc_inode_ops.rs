//! inode-D34: the `s_op` allocation lifecycle methods — `alloc_inode`
//! (default funnels through `InodeBuilder`, born `i_count == 1`), `free_inode`
//! and `destroy_inode` (default = drop the in-core inode). New defaulted
//! `SuperOps` methods so a backend CAN override allocation without breaking the
//! generic builder funnel.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, KResult, VfsError};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "tallocfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0xBEEF, 5, 4096, "tallocfs".into(), Arc::new(()))
}

/// Default `alloc_inode` builds a fresh inode via the `InodeBuilder` funnel:
/// correct ino/mode/type, born with `i_count == 1`.
#[test]
fn alloc_inode_funnels_through_builder() {
    let sb = sb();
    let i = sb.s_op.alloc_inode(
        99, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops());
    assert_eq!(i.ino(), 99);
    assert_eq!(i.file_type(), FileType::Regular);
    assert_eq!(i.i_mode() & 0o7777, 0o600);
    assert_eq!(i.i_count(), 1, "freshly allocated inode is born i_count == 1");
}

/// `free_inode` / `destroy_inode` default = drop: callable, consume the inode,
/// and don't touch any still-held reference's identity.
#[test]
fn free_and_destroy_inode_are_drop() {
    let sb = sb();
    let i = sb.s_op.alloc_inode(
        7, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops());
    let keep = i.clone();
    sb.s_op.destroy_inode(i); // consumes one Arc (the moved-in handle)
    assert_eq!(keep.ino(), 7, "the surviving reference is unaffected");
    sb.s_op.free_inode(keep); // consumes the last handle
}
