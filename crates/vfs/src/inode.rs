// `Inode` trait per `16§2`. Trait-object backed (`Arc<dyn Inode>`) so
// every FS impl (tmpfs / ext4 / procfs / devfs) shares one VFS surface.
//
// Subset for v1; the full ~30-method surface in spec lands as each
// FS-specific consumer needs it. Path resolution + FdTable +
// File::read/write are the immediate users — they need: ino /
// file_type / size / lookup / read / write / readdir.

extern crate alloc;
use alloc::sync::Arc;

use crate::types::{FileType, Ino, KResult, VfsError};

/// Per-component lookup hit. Negative dentries (`name` exists in cache
/// but resolves to no inode) are signalled by returning
/// `Err(VfsError::Enoent)` from `lookup`.
pub type InodeRef = Arc<dyn Inode>;

/// `16§2` Inode trait — v1 subset.
pub trait Inode: Send + Sync {
    /// # C: O(1)
    fn ino(&self) -> Ino;

    /// # C: O(1)
    fn file_type(&self) -> FileType;

    /// # C: O(1)
    fn size(&self) -> u64;

    /// Resolve `name` within this inode (must be a directory). Returns
    /// `Err(Enotdir)` for non-directory inodes; `Err(Enoent)` for
    /// missing names.
    /// # C: depends on FS impl
    fn lookup(&self, name: &str) -> KResult<InodeRef>;

    /// Read into `buf` starting at byte offset `off`. Returns the
    /// number of bytes actually read; `0` indicates EOF. Default impl
    /// returns `Err(Eisdir)` for directory inodes.
    /// # C: depends on FS impl
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Eisdir)
    }

    /// Write `buf` starting at byte offset `off`. Returns the number
    /// of bytes actually written. Default impl returns `Err(Eisdir)`.
    /// # C: depends on FS impl
    fn write(&self, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Eisdir)
    }

    /// Truncate the file to `len` bytes per `truncate(2)` /
    /// `ftruncate(2)`. Default impl returns `Erofs`. tmpfs honours
    /// it; static / pseudo inodes don't.
    /// # C: depends on FS impl
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Iterate child entries of a directory. `off` is the cookie from
    /// a previous call; `0` starts from the beginning. The callback
    /// returns `false` to stop early. Default impl returns
    /// `Err(Enotdir)`.
    /// # C: depends on FS impl
    fn readdir(
        &self,
        _off: u64,
        _f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        Err(VfsError::Enotdir)
    }
}
