// Dynamic `/proc` + `/sys` file inodes under the KEYSTONE struct-`Inode` model
// (`16§2`). A procfs leaf is now a concrete `vfs::Inode` whose `i_fop` renders
// the body on each read; per-inode state (a generator, a tid, an owned body)
// lives in `i_private`. These helpers stamp the common read-only shapes so the
// per-file modules carry only their body builder.
#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError};

const PROC_RO_FILE_MODE: u32 = 0o444;

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
    InodeBuilder::new(ino, mk_mode(FileType::Regular, PROC_RO_FILE_MODE), default_inode_ops(), Arc::new(GenFileOps))
        .private(Arc::new(GenData { gen }))
        .build()
}

/// `i_private` for a namespace-relative generator. `current_ns` is consulted
/// once per open; `gen` receives the captured id explicitly. # C: O(1)
pub struct NsGenData { pub current_ns: fn() -> u64, pub gen: fn(u64) -> Vec<u8> }

struct NsGenFileOps;
impl FileOps for NsGenFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<NsGenData>().ok_or(VfsError::Einval)?;
        let ns = (d.current_ns)();
        Ok(read_at(&(d.gen)(ns), off, buf))
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_open_body(file, off, buf)
    }
    fn read_nonblock_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_open_body(file, off, buf)
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<NsGenData>().ok_or(VfsError::Einval)?;
        let ns = (d.current_ns)();
        install_open_body(file, (d.gen)(ns));
        Ok(())
    }
    fn on_release_file(&self, file: &File) { release_open_body(file); }
}

/// Read-only task-relative file whose namespace and body are snapshotted at
/// open. Direct inode reads capture once for that read. # C: O(1)
pub fn make_ns_gen_file(ino: Ino, current_ns: fn() -> u64, gen: fn(u64) -> Vec<u8>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, PROC_RO_FILE_MODE), default_inode_ops(), Arc::new(NsGenFileOps))
        .private(Arc::new(NsGenData { current_ns, gen }))
        .build()
}

fn install_open_body(file: &File, body: Vec<u8>) {
    file.set_private_data(Box::into_raw(Box::new(body)) as u64);
}

fn read_open_body(file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
    let state = file.private_data();
    if state == 0 { return Err(VfsError::Einval); }
    // SAFETY: on_open_file installed this Box<Vec<u8>> and the open File owns
    // it unchanged until the final on_release_file invocation consumes it.
    let body = unsafe { &*(state as *const Vec<u8>) };
    Ok(read_at(body, off, buf))
}

fn release_open_body(file: &File) {
    let state = file.private_data();
    if state == 0 { return; }
    file.set_private_data(0);
    // SAFETY: nonzero private_data is one Box<Vec<u8>> installed at open, and
    // final release clears then consumes that exact allocation only once.
    unsafe { drop(Box::from_raw(state as *mut Vec<u8>)); }
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
    InodeBuilder::new(ino, mk_mode(FileType::Regular, PROC_RO_FILE_MODE), default_inode_ops(), Arc::new(PidGenFileOps))
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
    InodeBuilder::new(ino, mk_mode(FileType::Regular, PROC_RO_FILE_MODE), default_inode_ops(), Arc::new(OwnedFileOps))
        .private(Arc::new(OwnedData { body }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    use vfs::{Dentry, OpenFlags};

    static CURRENT_NS: AtomicU64 = AtomicU64::new(0);

    fn current_ns() -> u64 { CURRENT_NS.load(Ordering::SeqCst) }
    fn body(ns: u64) -> Vec<u8> { alloc::vec![b'0' + ns as u8, b'a', b'b'] }

    #[test]
    fn namespace_body_is_immutable_for_open_description() {
        CURRENT_NS.store(1, Ordering::SeqCst);
        let inode = make_ns_gen_file(crate::ids::NS_GENERATED, current_ns, body);
        let first = File::new(Arc::clone(&inode), Dentry::new_root(Arc::clone(&inode)), OpenFlags::O_RDONLY);
        first.open_hook().unwrap();

        let mut prefix = [0u8; 1];
        assert_eq!(first.read(&mut prefix).unwrap(), 1);
        assert_eq!(&prefix, b"1");

        CURRENT_NS.store(2, Ordering::SeqCst);
        let mut suffix = [0u8; 2];
        assert_eq!(first.read(&mut suffix).unwrap(), 2);
        assert_eq!(&suffix, b"ab");

        let dentry = Dentry::new_root(Arc::clone(&inode));
        let second = File::new(inode, dentry, OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK);
        second.open_hook().unwrap();
        let mut full = [0u8; 3];
        assert_eq!(second.read(&mut full).unwrap(), 3);
        assert_eq!(&full, b"2ab");
    }
}
