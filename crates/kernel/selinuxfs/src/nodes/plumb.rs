// The thin layer between a node's handler and the filesystem.
//
// One inode shape serves every non-transaction node: the body it reads and
// the write it accepts are two closures in `i_private`. Keeping the plumbing
// generic is what keeps the handlers pure — the decision each node makes
// lives in its own module and is reached the same way from a test as from a
// read.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::file_ops::FileOps;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::{mk_mode, InodeOps};
use vfs::{AddressSpaceOps, FileType, InodeRef, KResult, VfsError};

/// Handler a read reaches, given the file offset and the caller's buffer.
///
/// Reads carry the offset rather than a rendered body so a node whose content
/// is large — the policy image — answers a partial read without copying the
/// whole of it first.
pub type ReadFn = Box<dyn Fn(u64, &mut [u8]) -> KResult<usize> + Send + Sync>;
/// Handler a write reaches, given the file offset and the written bytes.
pub type WriteFn = Box<dyn Fn(u64, &[u8]) -> KResult<usize> + Send + Sync>;

/// Backend state of one node: what it renders and what it accepts.
pub struct DynFile {
    read: Option<ReadFn>,
    write: Option<WriteFn>,
}

/// Inode operations of a control node.
///
/// `truncate` succeeds because a shell redirection opens these with `O_TRUNC`
/// and there is nothing to truncate: refusing it would make `echo 1 > enforce`
/// fail before the write ever reached the handler.
struct CtlInodeOps;
impl InodeOps for CtlInodeOps {
    /// # C: O(1)
    fn truncate(&self, _inode: &Inode, _len: u64) -> KResult<()> { Ok(()) }
}

/// Inode-operations vector shared by every control node. # C: O(1)
pub fn ctl_inode_ops() -> Arc<dyn InodeOps> { Arc::new(CtlInodeOps) }

/// File operations of a node backed by [`DynFile`].
struct DynFileOps;
impl FileOps for DynFileOps {
    /// # C: O(body)
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<DynFile>().ok_or(VfsError::Einval)?;
        let read = data.read.as_ref().ok_or(VfsError::Eacces)?;
        read(off, buf)
    }

    /// # C: O(body) plus the handler
    ///
    /// The caller's bytes are COPIED before any handler sees them. `buf`
    /// points at user memory whose pages are only demand-faulted, so the first
    /// read of it can sleep — and a handler that first touches it while
    /// holding the security server's lock sleeps with preemption disabled.
    /// Copying here makes that impossible for every handler at once, rather
    /// than relying on each one to touch the buffer before it takes a lock.
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<DynFile>().ok_or(VfsError::Einval)?;
        let write = data.write.as_ref().ok_or(VfsError::Eacces)?;
        let body = dup_caller_bytes(buf)?;
        write(off, &body)
    }
}

/// Copy the part of `body` at `off` into `buf`. # C: O(buf)
pub fn copy_out(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let avail = &body[off..];
    let n = avail.len().min(buf.len());
    buf[..n].copy_from_slice(&avail[..n]);
    n
}

/// Copy caller-supplied bytes into kernel memory. # C: O(len)
///
/// Fallible rather than `to_vec`: the length comes from userspace, and an
/// allocation failure here must refuse the write, not abort the kernel.
pub fn dup_caller_bytes(buf: &[u8]) -> KResult<alloc::vec::Vec<u8>> {
    let mut out = alloc::vec::Vec::new();
    out.try_reserve_exact(buf.len()).map_err(|_| VfsError::Enomem)?;
    out.extend_from_slice(buf);
    Ok(out)
}

/// The part of `body` at `off`, at most `len` bytes, as an owned copy. # C: O(len)
///
/// For a reader that holds a lock: the destination is caller memory and
/// touching it can take a demand fault that sleeps, so the bytes are taken
/// under the lock and written out after it is dropped.
pub fn slice_at(body: &[u8], off: u64, len: usize) -> alloc::vec::Vec<u8> {
    let off = off as usize;
    if off >= body.len() { return alloc::vec::Vec::new(); }
    let avail = &body[off..];
    avail[..avail.len().min(len)].to_vec()
}

/// Build a node from its mode and its two handlers. # C: O(1)
pub fn dyn_file(perm: u16, read: Option<ReadFn>, write: Option<WriteFn>) -> InodeRef {
    InodeBuilder::new(crate::root::alloc_ino(), mk_mode(FileType::Regular, perm),
                      ctl_inode_ops(), Arc::new(DynFileOps))
        .fsid(crate::root::SELINUXFS_FSID)
        .private(Arc::new(DynFile { read, write }))
        .build()
}

/// Build a read-only node rendering `read`. # C: O(1)
pub fn ro_file(perm: u16, read: ReadFn) -> InodeRef { dyn_file(perm, Some(read), None) }

/// Build a read-only file whose regular reads use `read` while shared mmap
/// faults use the same inode-owned address space. # C: O(1)
pub fn mapped_ro_file(perm: u16, size: u64, mapping: Arc<dyn AddressSpaceOps>, read: ReadFn) -> InodeRef {
    InodeBuilder::new(crate::root::alloc_ino(), mk_mode(FileType::Regular, perm),
                      ctl_inode_ops(), Arc::new(DynFileOps))
        .size(size)
        .mapping(mapping)
        .private(Arc::new(DynFile { read: Some(read), write: None }))
        .fsid(crate::root::SELINUXFS_FSID)
        .build()
}

/// Build a write-only node accepting `write`. # C: O(1)
pub fn wo_file(perm: u16, write: WriteFn) -> InodeRef { dyn_file(perm, None, Some(write)) }

/// Turn a body-producing handler into an offset-taking one. # C: O(1)
pub fn body_reader(read: impl Fn() -> KResult<Vec<u8>> + Send + Sync + 'static) -> ReadFn {
    Box::new(move |off, buf| { let body = read()?; Ok(copy_out(&body, off, buf)) })
}

/// Build a node from a handler that renders text. # C: O(1)
pub fn text_file(perm: u16, read: impl Fn() -> String + Send + Sync + 'static) -> InodeRef {
    ro_file(perm, body_reader(move || Ok(read().into_bytes())))
}

#[cfg(test)]
#[path = "../tests/plumb.rs"]
mod tests;
