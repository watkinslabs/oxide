//! superblock D27 — sb freeze gate on the write(2) path + freeze/thaw round-trip.
//!
//! `File::write`/`pwrite`/`write_iter` now take `sb_start_write` (Linux
//! `file_start_write`) before the data dispatch: a write to a FROZEN superblock
//! is rejected with EROFS (documented approximation of Linux's block-until-thaw)
//! and re-admitted once `thaw_super` runs. `freeze_super`/`thaw_super` are what
//! the FIFREEZE/FITHAW ioctls invoke, so this exercises that round-trip too.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    default_inode_ops, mk_mode, Dentry, File, FileOps, FileType, Inode, InodeBuilder, InodeRef,
    KResult, OpenFlags, VfsError,
};

struct FrType;
impl FileSystemType for FrType {
    fn name(&self) -> &str { "frzfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct FrOps;
impl SuperOps for FrOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    // freeze_fs/thaw_fs use the trait no-op defaults (no on-disk backend here).
}

// A regular-file data path that always accepts the bytes — so a successful
// write returns the buffer length and the frozen-EROFS path is isolated to the
// sb gate, not a missing backend op.
struct AcceptOps;
impl FileOps for AcceptOps {
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(FrType), Arc::new(FrOps), 0x1234, 9, 4096, "frzfs".into(), Arc::new(()))
}
fn reg_inode(sb: &Arc<SuperBlock>) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(AcceptOps))
        .sb(Arc::downgrade(sb)).nlink(1).build()
}
fn rw_file(inode: &InodeRef) -> Arc<File> {
    let d = Dentry::new(None, "f".into(), inode.clone());
    File::new(inode.clone(), d, OpenFlags::O_RDWR)
}

#[test]
fn write_to_frozen_sb_is_erofs_then_thaw_readmits() {
    let sb = sb();
    let ino = reg_inode(&sb);
    let f = rw_file(&ino);

    // Unfrozen: write admitted, returns the byte count.
    assert_eq!(f.write(b"hello"), Ok(5), "unfrozen write admitted");
    assert_eq!(sb.sb_writers(), 0, "writer count balanced after write");

    // Freeze (FIFREEZE): now FROZEN at COMPLETE level.
    assert_eq!(sb.freeze_super(), Ok(()), "freeze_super succeeds");
    assert!(sb.is_frozen(), "sb reports frozen");

    // write/pwrite/writev to a frozen sb → EROFS (no leaked in-flight writer).
    assert_eq!(f.write(b"x"), Err(VfsError::Erofs), "write on frozen sb EROFS");
    assert_eq!(f.pwrite(b"x", 0), Err(VfsError::Erofs), "pwrite on frozen sb EROFS");
    assert_eq!(f.write_iter(&[b"x"]), Err(VfsError::Erofs), "writev on frozen sb EROFS");
    assert_eq!(sb.sb_writers(), 0, "no writer leaked across rejected writes");

    // Thaw (FITHAW): writes re-admitted.
    assert_eq!(sb.thaw_super(), Ok(()), "thaw_super succeeds");
    assert!(!sb.is_frozen(), "sb no longer frozen");
    assert_eq!(f.write(b"world!"), Ok(6), "write re-admitted after thaw");
    assert_eq!(sb.sb_writers(), 0, "writer count balanced after re-admitted write");
}

#[test]
fn fifreeze_fithaw_roundtrip_semantics() {
    let sb = sb();

    // FIFREEZE on an already-frozen sb → EBUSY.
    assert_eq!(sb.freeze_super(), Ok(()), "first freeze ok");
    assert_eq!(sb.freeze_super(), Err(VfsError::Ebusy), "second freeze EBUSY");

    // FITHAW resumes; a second FITHAW on an unfrozen sb → EINVAL.
    assert_eq!(sb.thaw_super(), Ok(()), "first thaw ok");
    assert_eq!(sb.thaw_super(), Err(VfsError::Einval), "thaw of unfrozen sb EINVAL");

    // Round-trip again to confirm the gate fully reset.
    assert_eq!(sb.freeze_super(), Ok(()), "re-freeze after thaw ok");
    assert!(sb.is_frozen());
    assert_eq!(sb.thaw_super(), Ok(()), "re-thaw ok");
    assert!(!sb.is_frozen());
}
