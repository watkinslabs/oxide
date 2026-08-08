// Per-OPERATION write behaviour — the `RWF_*` bits that `pwritev2`/`writev`
// carry on a single call, as opposed to the description-level `O_APPEND` /
// `O_NONBLOCK` state that `pwrite`/`write` already apply.
//
// Kept out of `io.rs` so the plain data paths stay one screen: this file owns
// only the "this one call asked for something different" cases.

use crate::types::{FileType, KResult, OpenFlags, VfsError};

use super::{File, Fmode};

/// Per-operation write modifiers resolved from the `RWF_*` word.
///
/// `append` is the EFFECTIVE append decision (already folded with the
/// description's `O_APPEND` by the caller's admission ladder), so this type
/// carries a decision, not a flag to re-derive.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct WriteIocb {
    /// Force the write to start at live `i_size`, ignoring the offset argument.
    pub append: bool,
    /// Never sleep for backing store: report `EAGAIN`, or `EOPNOTSUPP` when
    /// this description's write path cannot make that promise at all.
    pub nowait: bool,
}

impl File {
    /// `pwrite` with per-operation modifiers. `pwrite` itself is this with the
    /// description's own `O_APPEND` and no nowait, which is why it delegates
    /// here rather than keeping a second copy of the gate ladder.
    ///
    /// Gate order is `pwrite`'s: negative offset `EINVAL`, missing
    /// `FMODE_PWRITE` `ESPIPE`, missing `FMODE_WRITE` `EBADF`, read-only mount
    /// `EROFS`, then the freeze admission.
    ///
    /// `nowait` on a page-cache-backed regular file is `EOPNOTSUPP`, not a
    /// silent block: a buffered write has to be allowed to allocate, read a
    /// partial block back and wait on the journal, so no such path can honour
    /// "never wait". Answering `EOPNOTSUPP` is what a filesystem that has not
    /// opted its write side in reports; accepting the flag and then blocking
    /// would be the real defect, because a caller that asked never to wait
    /// would wait. # C: depends on inode impl
    pub fn pwrite_iocb(&self, buf: &[u8], off: i64, iocb: WriteIocb) -> KResult<usize> {
        if off < 0 { return Err(VfsError::Einval); }
        if !self.f_mode.contains(Fmode::PWRITE) { return Err(VfsError::Espipe); }
        if !self.f_mode.contains(Fmode::WRITE)  { return Err(VfsError::Ebadf); }
        if self.mnt_readonly() {
            #[cfg(feature = "debug-mnt")]
            self.trace_write_erofs(b"pwrite");
            return Err(VfsError::Erofs);
        }
        if iocb.nowait && self.write_blocks() { return Err(VfsError::Eopnotsupp); }
        // Freeze admission (`file_start_write`); the guard releases on every
        // return path below.
        let _sbw = self.file_start_write()?;
        let f = self.flags();
        let pos = if iocb.append { self.inode.size() } else { off as u64 };
        let buf = &buf[..self.write_limit(pos, buf.len())?];
        let n = if f.contains(OpenFlags::O_NONBLOCK) || iocb.nowait {
            self.f_op.write_nonblock(&self.inode, pos, buf)?
        } else {
            self.f_op.write(&self.inode, pos, buf)?
        };
        if n > 0 {
            self.file_update_time();
            super::fire_write_hook(&self.inode, &self.dentry);
            self.generic_write_sync(pos + n as u64, n, crate::file::SyncMode::default())?;
        }
        Ok(n)
    }

    /// True when this description's write path may have to wait for backing
    /// store it cannot skip — a regular file with a page-cache mapping, whose
    /// write goes through allocation and the journal. Streaming descriptions
    /// (pipe, socket, fifo) have a genuine non-blocking write and answer
    /// `EAGAIN` instead. # C: O(1)
    fn write_blocks(&self) -> bool {
        matches!(self.inode.file_type(), FileType::Regular) && self.inode.i_mapping().is_some()
    }
}
