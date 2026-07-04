extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::Ordering;

use crate::file_ops::HoleOrData;
use crate::types::{FileType, KResult, OpenFlags, VfsError};

use super::{fire_read_hook, fire_write_hook, File, Fmode, SeekFrom, PAGE_SIZE};

impl File {
    /// `read(2)` — advances the cursor by the byte count returned by
    /// the inode's `read`. Rejects writes-only opens with `Ebadf`.
    /// O_NONBLOCK routes through `Inode::read_nonblock`, which the
    /// blocking inodes (pipe/pty/tty/socket) override to return
    /// `EAGAIN` instead of parking.
    /// # C: depends on inode impl
    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let f = self.flags();
        // Gate on the canonical `f_mode` capability (Linux `rw_verify_area` /
        // `FMODE_READ`): O_WRONLY and O_PATH both lack FMODE_READ → EBADF.
        if !self.f_mode.contains(Fmode::READ) {
            return Err(VfsError::Ebadf);
        }
        // [D19] A directory fd has no readable byte stream: read(2)/readv(2) on
        // it is EISDIR (Linux `generic_read_dir`); getdents(2) is the only way to
        // read a directory. An O_RDONLY dir open carries FMODE_READ, so the EBADF
        // gate above passes — the EISDIR guard belongs here, after it.
        if matches!(self.inode.file_type(), FileType::Directory) {
            return Err(VfsError::Eisdir);
        }
        // FMODE_ATOMIC_POS: hold `f_pos_lock` across pos-read -> I/O ->
        // pos-update so a dup'd / CLONE_FILES-shared fd can't interleave the
        // cursor (Linux `__fdget_pos`). `None` for non-seekable files.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        let pos = self.pos.load(Ordering::Acquire);
        // D31: advance the per-open readahead window on the buffered read path
        // (Linux `page_cache_sync_readahead`). Regular files only; the window
        // state drives the block lane's page-cache fill. Pure state update — the
        // byte count returned is still bounded by `buf`, so there is no
        // over-read past EOF.
        if !f.contains(OpenFlags::O_NONBLOCK) && matches!(self.inode.file_type(), FileType::Regular) {
            let index = pos / PAGE_SIZE;
            let req = (((buf.len() as u64) + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as u32;
            let _ = self.ra_ondemand(index, req, false);
        }
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.read_nonblock_file(self, pos, buf)?
        } else {
            self.f_op.read_file(self, pos, buf)?
        };
        self.pos.store(pos + n as u64, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if n > 0 {
            fire_read_hook(&self.inode);
        }
        Ok(n)
    }

    /// `file_start_write` (Linux `fs/super.c` `sb_start_write` via the
    /// `vfs_write`/`write_iter` path): admit THIS description as an in-flight
    /// writer against its inode's superblock freeze gate before any data write,
    /// returning an RAII [`SbWriteGuard`] whose `Drop` runs `sb_end_write` on
    /// EVERY return/error path. Gated on regular files — freeze (SB_FREEZE_WRITE)
    /// protects on-disk filesystem data, and gating to `FileType::Regular`
    /// avoids holding the writer count across a parking pipe/socket write
    /// (which would wedge a freeze drain). An anon/regular file with no live
    /// superblock is not gated (its backend governs writability).
    ///
    /// CAVEAT (documented approximation): Linux `sb_start_write` SLEEPS on a
    /// frozen sb until `thaw_super`; there is no blocking writer wait-queue on
    /// this write path, so a NEW write to a FROZEN sb returns `Erofs` instead
    /// of blocking. The freeze itself still drains correctly — the level gate
    /// rejects new writers and `sb_writers()` tracks in-flight holders.
    /// # C: O(1)
    fn file_start_write(&self) -> KResult<SbWriteGuard> {
        if !matches!(self.inode.file_type(), FileType::Regular) {
            return Ok(SbWriteGuard(None));
        }
        match self.inode.i_sb() {
            Some(sb) => if sb.sb_start_write() { Ok(SbWriteGuard(Some(sb))) } else { Err(VfsError::Erofs) },
            None     => Ok(SbWriteGuard(None)),
        }
    }

    /// `write(2)` — advances the cursor by the byte count returned by
    /// the inode's `write`. Rejects read-only opens with `Ebadf`.
    /// `O_APPEND` snaps the offset to the current size before writing.
    /// # C: depends on inode impl
    pub fn write(&self, buf: &[u8]) -> KResult<usize> {
        let f = self.flags();
        // Gate on the canonical `f_mode` capability (Linux `FMODE_WRITE`):
        // O_RDONLY and O_PATH both lack FMODE_WRITE → EBADF.
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            return Err(VfsError::Erofs);
        }
        // D27: admit as a sb-freeze in-flight writer (Linux `file_start_write`).
        // EROFS if the sb is FROZEN; guard's Drop runs `sb_end_write` on every
        // return/error path below.
        let _sbw = self.file_start_write()?;
        // FMODE_ATOMIC_POS: hold `f_pos_lock` across the offset pick (incl.
        // the O_APPEND size read) -> I/O -> pos-update so a shared fd can't
        // interleave the cursor (Linux `__fdget_pos`). `None` for
        // non-seekable files. This serializes only THIS description's `pos`.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        // D37: O_APPEND cross-writer atomicity — hold the inode's `i_rwsem`
        // EXCLUSIVE across size-read -> write -> pos so two DIFFERENT open file
        // descriptions appending to the SAME inode are mutually atomic (Linux
        // `file_start_write` + the i_size append path's inode lock), not merely
        // per-description-serialized by `f_pos_lock`. Acquired AFTER `f_pos_lock`
        // (rank 35) — `i_rwsem` is rank 40, so the order is ascending. Gated on
        // `atomic_pos` (regular/dir) so the spin-rwsem is never held across a
        // parking pipe/socket write.
        let is_append = f.contains(OpenFlags::O_APPEND);
        let append_guard = if is_append && self.atomic_pos() { Some(self.inode.inode_lock()) } else { None };
        let off = if is_append {
            self.inode.size()
        } else {
            self.pos.load(Ordering::Acquire)
        };
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.write_nonblock(&self.inode, off, buf)?
        } else {
            self.f_op.write(&self.inode, off, buf)?
        };
        self.pos.store(off + n as u64, Ordering::Release);
        drop(append_guard); // release i_rwsem (rank 40) before f_pos_lock (rank 35)
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        // inotify IN_MODIFY hook (no-op when nothing installed).
        if n > 0 {
            fire_write_hook(&self.inode);
        }
        Ok(n)
    }

    /// `lseek(2)` SEEK_SET / CUR / END. Returns the new position.
    /// A resulting offset < 0 is rejected with `EINVAL`, matching Linux
    /// `vfs_setpos` / `default_llseek`: SEEK_SET with a negative `off`, or
    /// SEEK_CUR/END whose base+`off` is negative. The base+offset is computed
    /// in `i64` so a negative result can be detected before the unsigned store
    /// (the old `off as u64` cast turned a negative offset into a huge value).
    ///
    /// FMODE_LSEEK gate (Linux `vfs_llseek`): a file without FMODE_LSEEK is
    /// `ESPIPE` ("illegal seek") before any offset math. The bit is computed
    /// once at open (`new_at`): an `O_PATH` fd (FMODE_PATH only, `empty_fops`,
    /// no `llseek`) and an inherently non-seekable `pipe`/`socket`/`fifo` lack
    /// it — exactly the files Linux `do_dentry_open` leaves without
    /// FMODE_LSEEK. Regular/dir/char/block keep a real cursor and seek.
    /// # C: O(1)
    pub fn seek(&self, whence: SeekFrom, off: i64) -> KResult<u64> {
        if !self.f_mode.contains(Fmode::LSEEK) {
            return Err(VfsError::Espipe);
        }
        // SEEK_DATA(3)/SEEK_HOLE(4): the `off` arg is the START byte to scan
        // from (Linux `lseek` whence 3/4). A negative start is EINVAL; the
        // backend's `seek_hole_data` (generic: non-sparse, single EOF hole)
        // resolves it and returns ENXIO at/past EOF.
        if let SeekFrom::Data | SeekFrom::Hole = whence {
            if off < 0 { return Err(VfsError::Einval); }
            let which = if matches!(whence, SeekFrom::Hole) { HoleOrData::Hole } else { HoleOrData::Data };
            let new_pos = self.f_op.seek_hole_data(&self.inode, off as u64, which)?;
            self.pos.store(new_pos, Ordering::Release);
            return Ok(new_pos);
        }
        let base = match whence {
            SeekFrom::Start   => 0i64,
            SeekFrom::Current => self.pos.load(Ordering::Acquire) as i64,
            SeekFrom::End     => self.inode.size() as i64,
            // Data/Hole handled above and returned.
            SeekFrom::Data | SeekFrom::Hole => unreachable!(),
        };
        let new = base.checked_add(off).ok_or(VfsError::Einval)?;
        if new < 0 { return Err(VfsError::Einval); }
        let new_pos = new as u64;
        self.pos.store(new_pos, Ordering::Release);
        Ok(new_pos)
    }

    /// `pread(2)` / `pread64` — positional read at the explicit `off` that
    /// does NOT touch `f_pos` (Linux `ksys_pread64` → `vfs_read(file, buf,
    /// count, &pos)` over a LOCAL `pos`, bypassing `__fdget_pos`). Because no
    /// shared cursor is consulted or mutated, `f_pos_lock` is NOT taken —
    /// concurrent `pread`s on a dup'd / CLONE_FILES-shared fd are independent.
    /// Gate order mirrors Linux: a negative `off` is `EINVAL` before `fdget`;
    /// a file lacking FMODE_PREAD (a non-seekable pipe/socket/fifo, or an
    /// `O_PATH` fd with `empty_fops`) is `ESPIPE`; only then does the read
    /// capability (`FMODE_READ`) gate apply (`EBADF` for an `O_WRONLY` open).
    /// O_NONBLOCK routes through `read_nonblock` exactly as `read` does.
    /// # C: depends on inode impl
    pub fn pread(&self, buf: &mut [u8], off: i64) -> KResult<usize> {
        if off < 0 { return Err(VfsError::Einval); }
        // FMODE_PREAD gate (Linux `do_dentry_open`): only seekable files carry
        // it; pipe/socket/fifo and O_PATH fds do not → ESPIPE. The bit is set
        // once at open, so no per-call file-type re-derivation.
        if !self.f_mode.contains(Fmode::PREAD) {
            return Err(VfsError::Espipe);
        }
        if !self.f_mode.contains(Fmode::READ) {
            return Err(VfsError::Ebadf);
        }
        let f = self.flags();
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.read_nonblock(&self.inode, off as u64, buf)?
        } else {
            self.f_op.read(&self.inode, off as u64, buf)?
        };
        if n > 0 {
            fire_read_hook(&self.inode);
        }
        Ok(n)
    }

    /// `pwrite(2)` / `pwrite64` — positional write at the explicit `off` that
    /// does NOT touch `f_pos` (Linux `ksys_pwrite64` → `vfs_write` over a
    /// LOCAL `pos`, bypassing `__fdget_pos`), so `f_pos_lock` is NOT taken.
    /// Gate order mirrors Linux: negative `off` → `EINVAL`; a file lacking
    /// FMODE_PWRITE (pipe/socket/fifo or `O_PATH`) → `ESPIPE`; an unwritable
    /// open (`O_RDONLY`) → `EBADF`; a read-only mount → `EROFS`. The
    /// documented Linux O_APPEND quirk is preserved: with `O_APPEND` the
    /// effective offset is forced to the current size and `off` is IGNORED
    /// (`generic_write_checks` `IOCB_APPEND` overrides `ki_pos`) — see
    /// `pwrite(2)` BUGS. O_NONBLOCK routes through `write_nonblock`.
    /// # C: depends on inode impl
    pub fn pwrite(&self, buf: &[u8], off: i64) -> KResult<usize> {
        if off < 0 { return Err(VfsError::Einval); }
        // FMODE_PWRITE gate (Linux `do_dentry_open`): set once at open for
        // seekable files only; pipe/socket/fifo and O_PATH lack it → ESPIPE.
        if !self.f_mode.contains(Fmode::PWRITE) {
            return Err(VfsError::Espipe);
        }
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            return Err(VfsError::Erofs);
        }
        // D27: sb-freeze in-flight writer admission (Linux `file_start_write`);
        // EROFS on a FROZEN sb. Guard releases on every return path.
        let _sbw = self.file_start_write()?;
        let f = self.flags();
        // Linux pwrite + O_APPEND: IOCB_APPEND forces ki_pos = i_size,
        // ignoring the caller's offset (documented quirk, pwrite(2) BUGS).
        let pos = if f.contains(OpenFlags::O_APPEND) { self.inode.size() } else { off as u64 };
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.write_nonblock(&self.inode, pos, buf)?
        } else {
            self.f_op.write(&self.inode, pos, buf)?
        };
        if n > 0 {
            fire_write_hook(&self.inode);
        }
        Ok(n)
    }

    /// `readv(2)` core (Linux `vfs_readv` -> `do_iter_read`): aggregate the
    /// destination buffers into ONE cursor-advancing read, holding `f_pos_lock`
    /// for the WHOLE walk so a dup'd / shared fd cannot interleave the cursor,
    /// and advancing `f_pos` ONCE by the grand total (Linux `__fdget_pos`).
    /// Buffer `i` fills at the running offset `pos + total`; a short fill (`0` =
    /// EOF) ends the walk per `iov_iter`. An inode error propagates only when NO
    /// bytes were read yet, else the partial count is returned. Empty buffers
    /// skipped; O_NONBLOCK routes through `read_nonblock`. # C: O(sum of buf lens)
    pub fn read_iter(&self, bufs: &mut [&mut [u8]]) -> KResult<usize> {
        if !self.f_mode.contains(Fmode::READ) {
            return Err(VfsError::Ebadf);
        }
        let f = self.flags();
        let nonblock = f.contains(OpenFlags::O_NONBLOCK);
        // FMODE_ATOMIC_POS: one lock across the whole vectored op (Linux
        // `__fdget_pos`), so the cursor advances atomically over all buffers.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        let pos = self.pos.load(Ordering::Acquire);
        // D31: advance the readahead window once for the whole vectored read
        // (Linux `page_cache_sync_readahead`). Regular files only; the request
        // size is the grand total of the destination buffers. Pure state update.
        if !nonblock && matches!(self.inode.file_type(), FileType::Regular) {
            let bytes: u64 = bufs.iter().map(|b| b.len() as u64).sum();
            let index = pos / PAGE_SIZE;
            let req = ((bytes + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as u32;
            let _ = self.ra_ondemand(index, req, false);
        }
        let mut total: u64 = 0;
        for buf in bufs.iter_mut() {
            if buf.is_empty() { continue; }
            let want = buf.len();
            let off = pos + total;
            // D2: dispatch through the cached `file->f_op` (snapshotted at open).
            let r = if nonblock {
                self.f_op.read_nonblock_file(self, off, buf)
            } else {
                self.f_op.read_file(self, off, buf)
            };
            match r {
                Ok(0)                => break,                   // EOF
                Ok(n)                => { total += n as u64; if n < want { break; } }
                Err(e) if total == 0 => return Err(e),
                Err(_)               => break,                   // partial progress: keep it
            }
        }
        self.pos.store(pos + total, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if total > 0 {
            fire_read_hook(&self.inode);
        }
        Ok(total as usize)
    }

    /// `writev(2)` core (Linux `vfs_writev` -> `do_iter_write`): aggregate the
    /// source buffers into ONE cursor-advancing write, holding `f_pos_lock` for
    /// the whole walk and advancing `f_pos` ONCE by the total (Linux
    /// `__fdget_pos`). `O_APPEND` forces the base to i_size ONCE (Linux
    /// `IOCB_APPEND` for the whole iocb); inter-writer append atomicity is the
    /// inode lock's job. A short write ends the walk per `iov_iter`; an inode
    /// error propagates only with no prior progress, else the partial count.
    /// Empty buffers skipped; O_NONBLOCK → `write_nonblock`. # C: O(sum of buf lens)
    pub fn write_iter(&self, bufs: &[&[u8]]) -> KResult<usize> {
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            return Err(VfsError::Erofs);
        }
        // D27: sb-freeze in-flight writer admission (Linux `file_start_write`);
        // EROFS on a FROZEN sb. Guard releases on every return path.
        let _sbw = self.file_start_write()?;
        let f = self.flags();
        let nonblock = f.contains(OpenFlags::O_NONBLOCK);
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        // D37: O_APPEND cross-writer atomicity — hold `i_rwsem` EXCLUSIVE across
        // the size-read base pick -> the whole vectored write -> pos so two
        // DIFFERENT open descriptions appending stay mutually atomic (Linux
        // `IOCB_APPEND` under the append path's inode lock). Acquired after
        // `f_pos_lock` (35 -> 40, ascending); gated on `atomic_pos` so the
        // spin-rwsem is never held across a parking non-seekable write.
        let is_append = f.contains(OpenFlags::O_APPEND);
        let append_guard = if is_append && self.atomic_pos() { Some(self.inode.inode_lock()) } else { None };
        // O_APPEND forces the base to i_size ONCE for the whole vectored write.
        let base = if is_append { self.inode.size() } else { self.pos.load(Ordering::Acquire) };
        let mut total: u64 = 0;
        for buf in bufs.iter() {
            if buf.is_empty() { continue; }
            let want = buf.len();
            let off = base + total;
            // D2: dispatch through the cached `file->f_op` (snapshotted at open).
            let r = if nonblock { self.f_op.write_nonblock(&self.inode, off, buf) } else { self.f_op.write(&self.inode, off, buf) };
            match r {
                Ok(0)                => break,
                Ok(n)                => { total += n as u64; if n < want { break; } }
                Err(e) if total == 0 => return Err(e),
                Err(_)               => break,
            }
        }
        self.pos.store(base + total, Ordering::Release);
        drop(append_guard); // release i_rwsem (rank 40) before f_pos_lock (rank 35)
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if total > 0 {
            fire_write_hook(&self.inode);
        }
        Ok(total as usize)
    }
}

/// RAII pairing for [`SuperBlock::sb_start_write`]/[`SuperBlock::sb_end_write`]
/// (Linux `file_start_write`/`file_end_write`). Held across one
/// `write`/`pwrite`/`writev` so a concurrent `freeze_super` observes the
/// in-flight writer (`sb_writers()`); `Drop` releases it on every return/error
/// path. `None` = not freeze-gated (anon file / no superblock / non-regular).
/// # C: O(1)
struct SbWriteGuard(Option<Arc<crate::superblock::SuperBlock>>);
impl Drop for SbWriteGuard {
    fn drop(&mut self) {
        if let Some(sb) = self.0.take() { sb.sb_end_write(); }
    }
}
