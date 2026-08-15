//! The `vfs::File` a published loop device reads and writes through.
//!
//! Deliberately thin. Every rule about WHERE a byte goes lives in `size` and
//! `device`, which are tested against memory; this only carries a request the
//! device already validated to the description the caller opened, and turns
//! that description's errors into block-layer ones.

use alloc::sync::Arc;

use block::{BlockError, KResult};
use vfs::File;

use crate::device::Backing;

/// Positioned I/O against an open description.
///
/// The device holds the description, not a path: re-resolving a name would
/// let the file the device is backed by change underneath it, and a loop
/// device is defined by the description it was given.
pub struct FileBacking {
    file: Arc<File>,
    writable: bool,
}

impl FileBacking {
    /// Bind to an already-open description. `writable` is the caller's
    /// finding about the description's access mode, not a re-derivation:
    /// only the opener knows what it opened with. # C: O(1)
    pub fn new(file: Arc<File>, writable: bool) -> Self { Self { file, writable } }

    /// The description this device is backed by. # C: O(1)
    pub fn file(&self) -> &Arc<File> { &self.file }
}

/// A VFS error, as the block layer spells it. A description that has gone
/// away is `ENXIO` rather than a generic failure, so a caller can tell a
/// vanished backing store from a bad request. # C: O(1)
fn block_err(err: vfs::VfsError) -> BlockError {
    match err {
        vfs::VfsError::Enospc => BlockError::Enospc,
        vfs::VfsError::Einval => BlockError::Einval,
        vfs::VfsError::Enxio | vfs::VfsError::Ebadf => BlockError::Enxio,
        vfs::VfsError::Eagain => BlockError::Eagain,
        vfs::VfsError::Enomem => BlockError::Enomem,
        _ => BlockError::Eio,
    }
}

impl Backing for FileBacking {
    /// Read from the inode rather than caching a size: `LOOP_SET_CAPACITY`
    /// exists because the backing file's size changes under a bound device,
    /// and a cached size could not notice. # C: O(1)
    fn size_bytes(&self) -> u64 { self.file.inode().size() }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        if off > i64::MAX as u64 { return Err(BlockError::Eio); }
        self.file.pread(buf, off as i64).map_err(block_err)
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        if !self.writable { return Err(BlockError::Eio); }
        if off > i64::MAX as u64 { return Err(BlockError::Eio); }
        self.file.pwrite(buf, off as i64).map_err(block_err)
    }

    fn flush(&self) -> KResult<()> { self.file.vfs_fsync(false).map_err(block_err) }

    fn writable(&self) -> bool { self.writable }
}
