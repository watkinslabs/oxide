// Static read-only procfs/devfs file inode (fixed `&'static [u8]` body).
// Generic read-only inode with a fixed `&'static [u8]` body — used by
// procfs, devfs, and device-node crates alike. Lives in vfs (the base inode
// layer) so no consumer reaches into the kernel binary (docs/53).
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x3100_0000);

/// `0o444` — world-readable, no write bit. A [`StaticFileInode`] body is a
/// fixed `&'static [u8]` and `write` is unconditionally `Erofs`, so its
/// reported mode must NOT advertise an owner-write bit. The generic `Regular`
/// fallback (`getattr::default_perm_for`) returns `0o644`, which would lie
/// about being writable; Linux read-only pseudo files (`/proc/version`,
/// `/proc/filesystems`, …) are `-r--r--r--`, keeping `i_mode`/`stat` honest
/// with the `Erofs` write path.
const STATIC_PERM: u16 = 0o444;

pub struct StaticFileInode {
    body: &'static [u8],
    ino:  Ino,
}

impl StaticFileInode {
    /// # C: O(1)
    pub fn new(body: &'static [u8]) -> Arc<Self> {
        Arc::new(Self { body, ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) })
    }
}

impl Inode for StaticFileInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    /// Read-only `0o444` (see [`STATIC_PERM`]) — matches the `Erofs` write. # C: O(1)
    fn perm(&self) -> Option<u16> { Some(STATIC_PERM) }
    fn size(&self) -> u64 { self.body.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let off = off as usize;
        if off >= self.body.len() { return Ok(0); }
        let avail = &self.body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}
