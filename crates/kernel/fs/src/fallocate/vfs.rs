// `vfs_fallocate` (Linux `fs/open.c:250-352`) — everything `fallocate(2)`
// decides above the filesystem. The fd lookup stays in the syscall shim
// (`docs/53`), exactly as Linux keeps it in `ksys_fallocate`, so an invalid or
// `O_PATH` descriptor is `EBADF` before any argument here is looked at.

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::{File, FileType, SuperBlock};

use super::mode::{falloc_mode_ok, FALLOC_FL_KEEP_SIZE};

/// `S_SWAPFILE` (Linux `include/linux/fs.h`) — swapon captured this inode's
/// block map, so no operation may move its blocks.
const S_SWAPFILE: u32 = 1 << 8;

/// `-errno` in the syscall return convention. # C: O(1)
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `file_start_write`/`file_end_write` (Linux `fs/super.c` `sb_start_write`)
/// held across the backend call so a concurrent `freeze_super` counts this
/// allocation as an in-flight writer. `None` = no live superblock (anon file),
/// which is not freeze-gated. # C: O(1)
struct SbWriteGuard(Option<Arc<SuperBlock>>);

impl Drop for SbWriteGuard {
    fn drop(&mut self) { if let Some(sb) = self.0.take() { sb.sb_end_write(); } }
}

/// Admit this description as a freeze-gated writer. `Err` = the superblock is
/// read-only (`EROFS`), the same answer `mnt_want_write` gives. # C: O(1) or sleeps
fn file_start_write(file: &File) -> Result<SbWriteGuard, Errno> {
    match file.inode().i_sb() {
        Some(sb) => if sb.sb_start_write() { Ok(SbWriteGuard(Some(sb))) } else { Err(Errno::Erofs) },
        None     => Ok(SbWriteGuard(None)),
    }
}

/// `vfs_fallocate` (Linux `fs/open.c`) — the whole `fallocate(2)` ladder above
/// the filesystem, in Linux's order, returning `0` or `-errno`.
///
/// Order is load-bearing and is NOT the order the arguments suggest:
/// the range check owns the function's ONLY `EINVAL`; every unsupported mode
/// combination is `EOPNOTSUPP`; the writability check (`EBADF`) sits AFTER the
/// mode gate, so a bad mode on a read-only description reports the mode; the
/// inode-flag rejections (`EPERM`, `ETXTBSY`) precede the file-type ladder, so
/// an immutable directory is `EPERM` and not `EISDIR`; and the arithmetic /
/// `s_maxbytes` caps (`EFBIG`) come last, after the type is known good.
///
/// Not modelled: `security_file_permission` and `fsnotify_file_area_perm`
/// (steps 8-9 of the C function) are the LSM and fanotify permission-event
/// hooks; neither subsystem exists, and both are no-ops in a kernel without
/// them. The `!file->f_op->fallocate` test (step 14) needs no separate arm —
/// `InodeOps::fallocate` defaults to `Eopnotsupp`, which is the errno Linux
/// reports for a missing method.
///
/// `_cur` is the calling task the shim already resolved. Linux's
/// `vfs_fallocate` takes `(file, mode, offset, len)` and nothing task-scoped:
/// the ONE decision that needs the caller — `RLIMIT_FSIZE` plus its `SIGXFSZ`
/// — belongs to the filesystem's `inode_newsize_ok`, which reaches the current
/// task through the boot-installed hook. It is accepted here so the ABI shim
/// does not have to resolve `current` twice.
/// # C: backend-dependent
pub fn vfs_fallocate(_cur: &sched::Task, file: &File, mode: u32, offset: i64, len: i64) -> i64 {
    // 1. The single EINVAL. A zero-length request is an error, not a no-op.
    if offset < 0 || len <= 0 { return err(Errno::Einval); }
    // 2-3. Mode-combination gate — EOPNOTSUPP for everything it rejects.
    if let Err(e) = falloc_mode_ok(mode) { return err(e); }
    // 4. Writability. Linux tests `f_mode`, not `f_flags`, so `O_PATH` (which
    //    carries neither READ nor WRITE) is rejected here as well as by `fdget`.
    if !file.f_mode().contains(vfs::Fmode::WRITE) { return err(Errno::Ebadf); }
    let inode = file.inode();
    let i_flags = inode.i_flags();
    // 5. Append-only files admit space preallocation and nothing else: mode 0
    //    and bare KEEP_SIZE pass, every real mode bit is EPERM.
    if mode & !FALLOC_FL_KEEP_SIZE != 0 && i_flags & vfs::S_APPEND != 0 { return err(Errno::Eperm); }
    // 6. Immutable rejects even plain preallocation.
    if i_flags & vfs::S_IMMUTABLE != 0 { return err(Errno::Eperm); }
    // 7. An active swapfile's block map belongs to the swap subsystem.
    if i_flags & S_SWAPFILE != 0 { return err(Errno::Etxtbsy); }
    // 9-11. File-type ladder: three distinct errnos, none of them EINVAL.
    match inode.file_type() {
        FileType::Fifo      => return err(Errno::Espipe),
        FileType::Directory => return err(Errno::Eisdir),
        FileType::Regular | FileType::BlockDev => {}
        _                   => return err(Errno::Enodev),
    }
    // 12. `check_add_overflow(offset, len, &sum)` over signed loff_t.
    let Some(sum) = offset.checked_add(len) else { return err(Errno::Efbig) };
    // 13. The filesystem's largest representable file size. An inode with no
    //     live superblock (anon) has no cap to apply.
    if let Some(sb) = inode.i_sb() {
        if sum as u64 > sb.s_maxbytes() { return err(Errno::Efbig); }
    }
    // 15. Freeze-gated backend call. RLIMIT_FSIZE is deliberately NOT checked
    //     here: Linux leaves it to each filesystem's `inode_newsize_ok` call,
    //     which is why tmpfs enforces it even under KEEP_SIZE and ext4 does not.
    // fanotify FAN_PRE_ACCESS: allocating or punching a range changes the
    // file's content there, so a pre-content watcher is asked first and is told
    // which range.
    if let Err(e) = crate::inotify::check_file_area_perm(inode, true, Some(offset as u64), len as u64) {
        return err(e);
    }
    let guard = match file_start_write(file) { Ok(g) => g, Err(e) => return err(e) };
    let r = inode.fallocate(mode, offset as u64, len as u64);
    drop(guard);
    match r {
        // `fsnotify_modify` fires on success only, even when KEEP_SIZE left
        // `i_size` untouched — allocation is a modification.
        Ok(())  => { crate::inotify::fire_modify(inode); vfs::file::dnotify_emit(inode, vfs::file::DN_MODIFY); 0 }
        Err(e)  => -(e as i64),
    }
}
