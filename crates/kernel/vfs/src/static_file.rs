// Static read-only procfs/devfs file inode (fixed `&'static [u8]` body).
// Generic read-only inode with a fixed `&'static [u8]` body — used by
// procfs, devfs, and device-node crates alike. Lives in vfs (the base inode
// layer) so no consumer reaches into the kernel binary (docs/53).
//
// Post-KEYSTONE shape: the body lives in `i_private` (`StaticFileInode`), the
// read-from-body / `Erofs`-write data path is one shared `i_fop`
// (`StaticFileOps`), and `make_static_file_inode` stamps `S_IFREG|0o444`.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{FileType, InodeRef, KResult, VfsError};
use crate::inode::InodeBuilder;
use crate::inode_ops::default_inode_ops;
use crate::file_ops::FileOps;

static NEXT_INO: AtomicU64 = AtomicU64::new(0x3100_0000);

/// `0o444` — world-readable, no write bit. A static body is fixed and `write`
/// is unconditionally `Erofs`, so the reported mode must NOT advertise a write
/// bit (Linux read-only pseudo files are `-r--r--r--`). # C: O(1)
const STATIC_PERM: u16 = 0o444;

/// Backend-private state (`i_private`) for a static read-only file: the fixed
/// `&'static [u8]` body the `i_fop` reads. # C: O(1)
pub struct StaticFileInode {
    body: &'static [u8],
}

impl StaticFileInode {
    /// Build a static read-only file inode over `body`. Returns the concrete
    /// [`InodeRef`] (the old `Arc<StaticFileInode>` callers coerced anyway).
    /// # C: O(1)
    pub fn new(body: &'static [u8]) -> InodeRef { make_static_file_inode(body) }
}

/// `file_operations` for a static file — read slices the fixed body; write is
/// always `Erofs`. # C: O(buf)
struct StaticFileOps;
impl FileOps for StaticFileOps {
    fn read(&self, inode: &crate::inode::Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = match inode.private::<StaticFileInode>() { Some(d) => d.body, None => return Err(VfsError::Einval) };
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _inode: &crate::inode::Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// `make_static_file_inode` — the constructor every procfs/devfs static file
/// goes through: `S_IFREG|0o444`, `i_size = body.len()`, the body in
/// `i_private`, the shared read-only `i_fop`. # C: O(1)
pub fn make_static_file_inode(body: &'static [u8]) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mode = (FileType::Regular.to_ifmt() as u32) | (STATIC_PERM as u32);
    InodeBuilder::new(ino, mode, default_inode_ops(), Arc::new(StaticFileOps))
        .size(body.len() as u64)
        .private(Arc::new(StaticFileInode { body }))
        .build()
}
