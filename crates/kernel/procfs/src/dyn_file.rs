// Dynamic `/proc` + `/sys` file inodes under the KEYSTONE struct-`Inode` model
// (`16§2`). A procfs leaf is now a concrete `vfs::Inode` whose `i_fop` renders
// the body on each read; per-inode state (a generator, a tid, an owned body)
// lives in `i_private`. These helpers stamp the common read-only shapes so the
// per-file modules carry only their body builder.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError};

/// Copy `body[off..]` into `buf`; returns bytes copied (`0` = EOF). # C: O(min)
pub fn read_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&body[off..off + n]);
    n
}

/// `i_private` for a zero-arg generator file (body recomputed each read). # C: O(1)
pub struct GenData { pub gen: fn() -> Vec<u8> }

struct GenFileOps;
impl FileOps for GenFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<GenData>().ok_or(VfsError::Einval)?;
        Ok(read_at(&(d.gen)(), off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// Read-only dynamic `/proc` file: fixed `ino`, `S_IFREG|0o444`, body from
/// `gen()`. # C: O(1)
pub fn make_gen_file(ino: Ino, gen: fn() -> Vec<u8>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(GenFileOps))
        .private(Arc::new(GenData { gen }))
        .build()
}

/// `i_private` for a pid-parameterised generator file. # C: O(1)
pub struct PidGenData { pub tid: u32, pub gen: fn(u32) -> Vec<u8> }

struct PidGenFileOps;
impl FileOps for PidGenFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<PidGenData>().ok_or(VfsError::Einval)?;
        Ok(read_at(&(d.gen)(d.tid), off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// Read-only `/proc/<pid>/<file>` whose body is `gen(tid)`. # C: O(1)
pub fn make_pid_gen_file(ino: Ino, tid: u32, gen: fn(u32) -> Vec<u8>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(PidGenFileOps))
        .private(Arc::new(PidGenData { tid, gen }))
        .build()
}

/// `i_private` holding a once-computed owned body (e.g. a `/sys` attribute
/// snapshotted at lookup). # C: O(1)
pub struct OwnedData { pub body: Vec<u8> }

struct OwnedFileOps;
impl FileOps for OwnedFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<OwnedData>().ok_or(VfsError::Einval)?;
        Ok(read_at(&d.body, off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// Read-only file with a fixed owned body. # C: O(1)
pub fn make_owned_file(ino: Ino, body: Vec<u8>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(OwnedFileOps))
        .private(Arc::new(OwnedData { body }))
        .build()
}
