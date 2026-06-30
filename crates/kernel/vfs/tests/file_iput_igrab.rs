//! inode-D3: an open `File` (`struct file`) pins its inode with an `i_count`
//! reference — `igrab` at open (`File::new_at`), `iput` at the last close
//! (`File::drop`, the production `__fput`→`iput` path). Before D3 `.iput(` had
//! ZERO callers; the live reclaim was Arc-drop + `Weak` only. This proves the
//! open/close pair now drives `i_count` and that the pairing is balanced for
//! both a superblock-backed inode (routed through `SuperBlock::iput`) and an
//! anon inode (no superblock / icache: balanced in place).

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    default_file_ops, default_inode_ops, mk_mode, Dentry, File, FileType, InodeBuilder, InodeRef,
    KResult, OpenFlags, VfsError,
};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "tiputfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0xF00D, 7, 4096, "tiputfs".into(), Arc::new(()))
}
fn reg(ino: u64, sb: Option<&Arc<SuperBlock>>) -> InodeRef {
    let b = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops());
    match sb { Some(s) => b.sb(Arc::downgrade(s)).build(), None => b.build() }
}

/// SB-backed inode: open igrabs (1→2), last close iputs through
/// `SuperBlock::iput` (2→1). The igrab guarantees the count is ≥2 at drop, so
/// the iput is never the 1→0 evicting drop while the inode is open.
#[test]
fn open_close_balances_i_count_sb_backed() {
    let sb = sb();
    let ino = reg(11, Some(&sb));
    assert_eq!(ino.i_count(), 1, "fresh inode born i_count == 1");

    let d = Dentry::new(None, "f".into(), ino.clone());
    let f = File::new(ino.clone(), d, OpenFlags::O_RDWR);
    assert_eq!(ino.i_count(), 2, "open took one i_count ref (igrab)");

    drop(f);
    assert_eq!(ino.i_count(), 1, "close released the i_count ref (iput)");
}

/// Two opens of one inode each take + release their own ref; the count tracks
/// the live open-file-description count.
#[test]
fn two_opens_two_refs() {
    let sb = sb();
    let ino = reg(12, Some(&sb));
    let d1 = Dentry::new(None, "a".into(), ino.clone());
    let d2 = Dentry::new(None, "b".into(), ino.clone());
    let f1 = File::new(ino.clone(), d1, OpenFlags::O_RDONLY);
    let f2 = File::new(ino.clone(), d2, OpenFlags::O_RDONLY);
    assert_eq!(ino.i_count(), 3, "two opens → two extra refs over the build ref");
    drop(f2);
    assert_eq!(ino.i_count(), 2);
    drop(f1);
    assert_eq!(ino.i_count(), 1);
}

/// Anon inode (no superblock / icache): the open still igrabs and the close
/// balances it in place (no `SuperBlock::iput` available), never underflowing.
#[test]
fn open_close_balances_i_count_anon() {
    let ino = reg(13, None);
    assert!(ino.i_sb().is_none(), "anon inode has no superblock");
    assert_eq!(ino.i_count(), 1);
    let d = Dentry::new(None, "p".into(), ino.clone());
    let f = File::new(ino.clone(), d, OpenFlags::O_RDWR);
    assert_eq!(ino.i_count(), 2, "open igrabbed");
    drop(f);
    assert_eq!(ino.i_count(), 1, "close balanced the count in place");
}
