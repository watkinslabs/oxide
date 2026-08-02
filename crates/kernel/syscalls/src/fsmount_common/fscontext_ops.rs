// `read(2)` on the descriptor `fsopen(2)`/`fspick(2)` returns.
//
// The context accumulates one message per rejected parameter, per warning and
// per informational note, and this is the only way userspace ever sees them: a
// rejected `fsconfig(2)` reports EINVAL and nothing else, so a caller that
// cannot read the log knows an option was refused but never WHICH, or why.
//
// The decision — which message, whether it fits, what an empty ring means —
// lives in `vfs::fs::FsContext::fetch_message`, which is ungated and therefore
// testable. This file is the shim: take the lock, ask, copy out.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::{FileOps, Inode, KResult, VfsError};

use super::objects::FsContextInode;

pub struct FsContextFileOps;

impl FileOps for FsContextFileOps {
    /// One message per call, oldest first.
    ///
    /// - an empty ring is `ENODATA`, not a short read: end-of-file would tell a
    ///   caller the context is finished when it is merely quiet;
    /// - a message longer than the buffer is `EMSGSIZE` and STAYS QUEUED, so
    ///   the caller can retry larger — a truncating read would destroy the one
    ///   copy of the diagnostic;
    /// - the return is the byte count, terminating newline included and no NUL.
    ///
    /// The file offset is ignored: the log is a queue, not a byte stream, and a
    /// seek cannot address a message that has already been consumed.
    /// # C: O(len msg)
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let ctx = inode.private::<FsContextInode>().ok_or(VfsError::Einval)?;
        let mut g = ctx.fc.lock();
        let fc = g.as_mut().ok_or(VfsError::Einval)?;
        match fc.fetch_message(buf.len())? {
            None => Err(VfsError::Enodata),
            Some(msg) => {
                let n = msg.len();
                buf[..n].copy_from_slice(msg.as_bytes());
                Ok(n)
            }
        }
    }
}

/// # C: O(1)
pub fn fscontext_file_ops() -> Arc<dyn FileOps> { Arc::new(FsContextFileOps) }
