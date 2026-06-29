//! `File::read` on a directory fd → EISDIR (syscalls-D19). Linux
//! `generic_read_dir` returns -EISDIR for read(2)/readv(2) on a directory; the
//! only way to read a directory is getdents(2). A directory opened O_RDONLY
//! carries FMODE_READ, so the EBADF gate passes and the EISDIR guard fires.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
          default_inode_ops, mk_mode};

/// `i_fop` whose `read` would succeed — so the ONLY thing that can produce
/// EISDIR is the directory guard under test (not a missing read op).
struct OkOps;
impl FileOps for OkOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn file_of(ft: FileType) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x7777, mk_mode(ft, 0o755), default_inode_ops(), Arc::new(OkOps)).build();
    let dentry = Dentry::new(None, "d".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

#[test]
fn read_on_directory_is_eisdir() {
    let f = file_of(FileType::Directory);
    assert!(f.f_mode().contains(vfs::Fmode::READ), "O_RDONLY dir open carries FMODE_READ (so not EBADF)");
    assert_eq!(f.read(&mut [0u8; 8]), Err(VfsError::Eisdir),
        "read(2) on a directory fd must be EISDIR (Linux generic_read_dir)");
}

#[test]
fn read_on_regular_is_not_eisdir() {
    let f = file_of(FileType::Regular);
    assert_ne!(f.read(&mut [0u8; 8]), Err(VfsError::Eisdir),
        "a regular file read must not be spuriously EISDIR");
}
