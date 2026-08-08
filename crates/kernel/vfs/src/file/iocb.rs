// Per-OPERATION write behaviour — the `RWF_*` bits that `pwritev2`/`writev`
// carry on a single call, as opposed to the description-level `O_APPEND` /
// `O_NONBLOCK` state that `pwrite`/`write` already apply.
//
// Kept out of `io.rs` so the plain data paths stay one screen: this file owns
// only the "this one call asked for something different" cases.

use core::sync::atomic::Ordering;

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
    /// More data follows this buffer immediately, so a description that forms
    /// network segments may hold it back and coalesce with the next write.
    /// Only a segment-forming backend consumes it; every other write path
    /// ignores it, exactly as a hint should behave.
    pub more: bool,
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
    /// would wait.
    ///
    /// `iocb.more` has no destination here: a positional write needs
    /// `FMODE_PWRITE`, which no segment-forming description carries, so the
    /// hint is dropped rather than routed to a backend that cannot use it.
    /// # C: depends on inode impl
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

    /// `write(2)` with per-operation modifiers — the description-cursor write
    /// ladder. `write` itself is this call with the description's own
    /// `O_APPEND` and no per-operation modifiers, so there is exactly one copy
    /// of the gate order, the `f_pos_lock`/`i_rwsem` acquisition order and the
    /// post-write hook sequence.
    ///
    /// Unlike [`Self::pwrite_iocb`], the backend is reached through the
    /// hint-carrying `f_op->write` entry, because this is the path a
    /// segment-forming description (a socket) is written through: the plain
    /// blocking / non-blocking entries remain the default that entry forwards
    /// to, so a backend that ignores the hint keeps its existing behaviour.
    /// # C: depends on inode impl
    pub fn write_iocb(&self, buf: &[u8], iocb: WriteIocb) -> KResult<usize> {
        #[cfg(feature = "debug-zram-lifecycle")]
        klog::write_raw(b"[ZRAM-TEST] vfs-write-enter\n");
        let f = self.flags();
        // Gate on the canonical `f_mode` capability (Linux `FMODE_WRITE`):
        // O_RDONLY and O_PATH both lack FMODE_WRITE → EBADF.
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            #[cfg(feature = "debug-mnt")]
            self.trace_write_erofs(b"write");
            return Err(VfsError::Erofs);
        }
        if iocb.nowait && self.write_blocks() { return Err(VfsError::Eopnotsupp); }
        // D27: admit as a sb-freeze in-flight writer (Linux `file_start_write`).
        // Frozen sb sleeps until thaw; guard's Drop runs `sb_end_write` on every
        // return/error path below.
        let _sbw = self.file_start_write()?;
        #[cfg(feature = "debug-zram-lifecycle")]
        klog::write_raw(b"[ZRAM-TEST] vfs-write-sb\n");
        // FMODE_ATOMIC_POS: hold `f_pos_lock` across the offset pick (incl.
        // the O_APPEND size read) -> I/O -> pos-update so a shared fd can't
        // interleave the cursor (Linux `__fdget_pos`). `None` for
        // non-seekable files. This serializes only THIS description's `pos`.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        #[cfg(feature = "debug-zram-lifecycle")]
        klog::write_raw(b"[ZRAM-TEST] vfs-write-pos\n");
        // D37: O_APPEND cross-writer atomicity — hold the inode's `i_rwsem`
        // EXCLUSIVE across size-read -> write -> pos so two DIFFERENT open file
        // descriptions appending to the SAME inode are mutually atomic (Linux
        // `file_start_write` + the i_size append path's inode lock), not merely
        // per-description-serialized by `f_pos_lock`. Acquired AFTER `f_pos_lock`
        // (rank 35) — `i_rwsem` is rank 40, so the order is ascending. Gated on
        // `atomic_pos` so the spin-rwsem is never held across a parking
        // pipe/socket write.
        let append_guard = if iocb.append && self.atomic_pos() { Some(self.inode.inode_lock()) } else { None };
        #[cfg(feature = "debug-zram-lifecycle")]
        klog::write_raw(b"[ZRAM-TEST] vfs-write-append\n");
        let off = if iocb.append { self.inode.size() } else { self.pos.load(Ordering::Acquire) };
        let buf = &buf[..self.write_limit(off, buf.len())?];
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let nonblock = f.contains(OpenFlags::O_NONBLOCK) || iocb.nowait;
        let n = self.f_op.write_more_file(self, off, buf, nonblock, iocb.more)?;
        #[cfg(feature = "debug-zram-lifecycle")]
        klog::write_raw(b"[ZRAM-TEST] vfs-write-fop\n");
        self.pos.store(off + n as u64, Ordering::Release);
        drop(append_guard); // release i_rwsem (rank 40) before f_pos_lock (rank 35)
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        // inotify IN_MODIFY hook (no-op when nothing installed).
        if n > 0 {
            self.file_update_time();
            super::fire_write_hook(&self.inode, &self.dentry);
            self.generic_write_sync(off + n as u64, n, crate::file::SyncMode::default())?; // `generic_write_sync`
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
