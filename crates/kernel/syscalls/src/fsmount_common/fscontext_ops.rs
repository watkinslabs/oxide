// `read(2)` on the descriptor `fsopen(2)`/`fspick(2)` returns.
//
// The context accumulates one message per rejected parameter, per warning and
// per informational note, and this is the only way userspace ever sees them: a
// rejected `fsconfig(2)` reports EINVAL and nothing else, so a caller that
// cannot read the log knows an option was refused but never WHICH, or why.
//
// The decision — which message, whether it fits, what an empty ring means, and
// how many bytes come back — lives in `vfs::fs::FsContext::read_message`, which
// is ungated and therefore testable. This file is the shim: take the lock, ask.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::{FileOps, Inode, KResult, VfsError};

use super::objects::FsContextInode;

pub struct FsContextFileOps;

impl FileOps for FsContextFileOps {
    /// One message per call, oldest first: `ENODATA` on an empty ring,
    /// `EMSGSIZE` for a message that does not fit (left queued), otherwise the
    /// byte count. See `vfs::fs::FsContext::read_message`, which decides all of
    /// it. # C: O(len msg)
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let ctx = inode.private::<FsContextInode>().ok_or(VfsError::Einval)?;
        let mut g = ctx.fc.lock();
        g.as_mut().ok_or(VfsError::Einval)?.read_message(buf)
    }
}

/// # C: O(1)
pub fn fscontext_file_ops() -> Arc<dyn FileOps> { Arc::new(FsContextFileOps) }
