//! inode-D3 / D37 (production eviction): the create/lookup caller releases the
//! build/born `i_count` reference once a durable counted holder (dentry alias +
//! open `File`) is in place — Linux `do_last`/`d_instantiate` consuming the iget
//! ref. This models the PRODUCTION open(O_CREAT)+unlink+close sequence at the VFS
//! API level (the syscalls cannot run hosted) and proves the unlinked inode is
//! ACTUALLY freed (`i_count` 1→0 → `drop_inode` → `evict_inode`) on the last
//! close. The negative control shows that WITHOUT the born-ref release the inode
//! is stuck at `i_count == 1` forever and never evicts.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    d_add, d_make_root, default_file_ops, default_inode_ops, mk_mode, File, FileType,
    InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "ticfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0xF11D, 7, 4096, "ticfs".into(), Arc::new(()))
}
fn inode(sb: &Arc<SuperBlock>, ino: u64, ft: FileType, nlink: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(ft, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).nlink(nlink).build()
}
fn root(sb: &Arc<SuperBlock>) -> Arc<vfs::Dentry> {
    d_make_root(inode(sb, 1, FileType::Directory, 2), sb)
}

/// PRODUCTION create→open→unlink→close, WITH the D3/D37 born-ref release:
/// the inode is freed exactly on the last close.
#[test]
fn created_then_unlinked_then_closed_is_evicted() {
    let sb = sb();
    let r = root(&sb);

    // create(): backend builds the new inode born `i_count == 1`, nlink 1.
    let ino = inode(&sb, 30, FileType::Regular, 1);
    assert_eq!(ino.i_count(), 1, "fresh create: born i_count == 1");

    // open: bind to a dentry alias (`d_add` grab) then an open File (`igrab`).
    let d = d_add(&r, "f", ino.clone()); // born1 + alias = 2
    let file = File::new(ino.clone(), d.clone(), OpenFlags::O_RDWR); // + file = 3
    assert_eq!(ino.i_count(), 3, "alias + open file both count");

    // D3/D37 FIX: release the build/born reference now that durable holders exist
    // (Linux `do_last`/`d_instantiate` consumes the iget ref). vfs::file::iput.
    vfs::file::iput(ino.clone()); // 3 → 2
    assert_eq!(ino.i_count(), 2, "born ref released; alias + file remain");
    assert!(sb.ilookup(30).is_some(), "still held → alive");

    // unlink(): nlink → 0 and the directory entry's dentry alias is dropped.
    ino.set_nlink(0);
    vfs::dcache::d_delete(&d); // alias release: 2 → 1 (file still open)
    assert_eq!(ino.i_count(), 1, "only the open-file hold remains");
    assert!(sb.ilookup(30).is_some(), "open fd keeps the unlinked inode alive (no premature evict)");

    // close(): last reference → iput 1 → 0 → drop_inode(nlink 0) → evict_inode.
    drop(file);
    assert!(sb.ilookup(30).is_none(), "last close of an unlinked inode evicts it (i_count 0)");
}

/// NEGATIVE CONTROL: omit the born-ref release (the pre-fix behaviour). The born
/// reference is never accounted for, so `i_count` floors at 1 and the unlinked
/// inode is NEVER evicted — the exact leak D3/D37 closes.
#[test]
fn without_born_release_unlinked_inode_leaks() {
    let sb = sb();
    let r = root(&sb);

    let ino = inode(&sb, 31, FileType::Regular, 1); // born = 1
    let d = d_add(&r, "g", ino.clone()); // + alias = 2
    let file = File::new(ino.clone(), d.clone(), OpenFlags::O_RDWR); // + file = 3
    // (no vfs::file::iput here — simulates the un-fixed caller)

    ino.set_nlink(0);
    vfs::dcache::d_delete(&d); // 3 → 2
    drop(file); // 2 → 1

    assert_eq!(ino.i_count(), 1, "born ref unreleased → i_count stuck at 1");
    assert!(sb.ilookup(31).is_some(), "never evicted: the leak the born-ref release fixes");
}
