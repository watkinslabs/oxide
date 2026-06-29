//! file-D2: `File` caches `file->f_op` (an `Arc<dyn FileOps>` snapshotted from
//! `inode->i_fop` at open) and the data path dispatches through it, matching
//! Linux's per-`struct file` `f_op`. These prove the read/write/vectored paths
//! resolve against the backend `FileOps` via the cached vtable.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{
    default_inode_ops, mk_mode, Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult,
    OpenFlags,
};

/// Backend `FileOps`: read fills a constant byte, write reports the length.
struct MarkOps;
impl FileOps for MarkOps {
    fn read(&self, _i: &Inode, _off: u64, b: &mut [u8]) -> KResult<usize> {
        for x in b.iter_mut() { *x = 0xAB; }
        Ok(b.len())
    }
    fn write(&self, _i: &Inode, _off: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

fn file(flags: OpenFlags) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(
        11, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(MarkOps)).build();
    let d = Dentry::new(None, "f".into(), ino.clone());
    File::new(ino, d, flags)
}

#[test]
fn read_dispatches_through_cached_fop() {
    let f = file(OpenFlags::O_RDONLY);
    let mut buf = [0u8; 8];
    let n = f.read(&mut buf).unwrap();
    assert_eq!(n, 8);
    assert!(buf.iter().all(|&b| b == 0xAB), "bytes came from the backend f_op->read");
}

#[test]
fn write_dispatches_through_cached_fop() {
    let f = file(OpenFlags::O_WRONLY);
    let n = f.write(&[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(n, 5, "length came from the backend f_op->write");
}

#[test]
fn vectored_read_dispatches_through_cached_fop() {
    let f = file(OpenFlags::O_RDONLY);
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let total = {
        let mut bufs: [&mut [u8]; 2] = [&mut a, &mut b];
        f.read_iter(&mut bufs).unwrap()
    };
    assert_eq!(total, 8);
    assert!(a.iter().chain(b.iter()).all(|&x| x == 0xAB), "vectored read used f_op");
}
