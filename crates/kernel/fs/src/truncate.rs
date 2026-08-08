// `truncate(2)` / `ftruncate(2)` work-fns, matching the observable ABI of
// the path (`vfs_truncate`) and descriptor (`do_ftruncate`) size-change
// forms plus the `inode_newsize_ok` size gate. The syscall shims own only
// argument fetch and path/fd resolution.

use syscall::errno::Errno;
use vfs::{File, FileType, InodeRef, VfsPath};

/// A soft `RLIMIT_FSIZE` violation delivers `SIGXFSZ` to the current task
/// before the size-change call reports `EFBIG`. Hosted builds have no signal
/// machinery. # C: O(1)
fn send_sigxfsz() {
    #[cfg(target_os = "oxide-kernel")]
    sched::live::sigpend::send_signal_self(sched::live::sigpend::Signum::Sigxfsz);
}

/// Wall-clock stamp for the `mtime`/`ctime` a size change records (Linux
/// `current_time(inode)` reads `ktime_get_coarse_real_ts64` — CLOCK_REALTIME,
/// not the monotonic counter). This used to read the arch monotonic timer,
/// which made every `truncate`/`ftruncate` record `1970-01-01 + uptime`.
/// # C: O(1)
fn wall_now_ns() -> u64 { vfs::inode_times::realtime_now_ns() }

/// `RLIMIT_FSIZE` half of Linux `inode_newsize_ok`, installed into VFS at boot
/// by [`install_rlimit_fsize_hook`]. `false` means the new size exceeds the
/// caller's SOFT limit; `SIGXFSZ` is posted first, exactly like the write path.
/// # C: O(1)
fn rlimit_fsize_allows(offset: u64) -> bool {
    let Some(cur) = sched::current() else { return true };
    let limit = cur.rlimit(sched::rlimit::rlim::FSIZE).0;
    if limit == sched::rlimit::INFINITY || offset <= limit { return true; }
    send_sigxfsz();
    false
}

/// Hand VFS the rlimit/signal decision it cannot reach on its own. Boot, once.
/// # C: O(1)
pub fn install_rlimit_fsize_hook() { vfs::set_rlimit_fsize_hook(rlimit_fsize_allows); }

/// Common size-change body shared by the path and descriptor truncate forms:
/// drop set-user-ID / set-group-ID privilege bits the size change would
/// invalidate, then apply an attr-change carrying `ATTR_SIZE` plus whatever
/// timestamp bits the caller wants. The `RLIMIT_FSIZE` / max-file-size gate
/// lives one level down, in attr-change validation, so every `ATTR_SIZE`
/// path (`O_TRUNC` open, `file_setattr`) shares it.
///
/// `times` is `0` for the path form and `ATTR_MTIME | ATTR_CTIME` for the
/// descriptor form — the same split between the path and descriptor forms.
///
/// `ATTR_FORCE` is always set: both callers have already established write
/// authority (`inode_permission(MAY_WRITE)` for the path form, `FMODE_WRITE`
/// for the descriptor form), and Linux does not re-derive it inside
/// `notify_change`. # C: O(1)
pub fn do_truncate(inode: &InodeRef, mnt_id: u64, len: u64, times: u32, cred: &vfs::Cred) -> i64 {
    let mut valid = vfs::ATTR_SIZE | vfs::ATTR_FORCE | times;
    // A size change drops the privilege bits, so a set-user-ID binary
    // cannot be re-shaped and keep its setid.
    valid |= vfs::setattr_should_drop_suidgid(inode.as_ref(), cred);
    let now = wall_now_ns();
    let mut ia = vfs::Iattr {
        valid,
        size: len,
        mtime: vfs::Timespec64::from_clock_ns(now),
        ctime: vfs::Timespec64::from_clock_ns(now),
        ..Default::default()
    };
    match vfs::notify_change_mnt(inode, mnt_id, &mut ia, cred, now) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}

/// `truncate(2)` path form. Error order: 1) type gate (`EISDIR` for a
/// directory, `EINVAL` for any other non-regular file), 2) write permission
/// check (`EACCES`), 3) mount read-only gate (`EROFS`) and append-only
/// reject (`EPERM`) inside the attr-change apply. # C: O(1)
pub fn vfs_truncate(vp: &VfsPath, len: u64, cred: &vfs::Cred) -> i64 {
    match vp.inode.file_type() {
        // "For directories it's -EISDIR, for other non-regulars - -EINVAL".
        FileType::Directory => return -(Errno::Eisdir.as_i32() as i64),
        FileType::Regular   => {}
        _                   => return -(Errno::Einval.as_i32() as i64),
    }
    if let Err(e) = vfs::inode_permission(&vp.inode, vfs::MAY_WRITE, cred) {
        return -(e as i64);
    }
    // Linux `vfs_truncate` takes `get_write_access` here — after the permission
    // and append checks, before the lease break. It fails `ETXTBSY` while any
    // task is executing this inode, which is what stops a running binary's text
    // being rewritten under it. Released immediately after (`put_write_and_out`).
    // fanotify FAN_PRE_ACCESS: a pre-content watcher fills the content a
    // truncate is about to cut or extend, so it is asked BEFORE the size
    // changes and is told the range holding the new end.
    if let Err(e) = crate::inotify::check_truncate_perm(&vp.inode, len) {
        return -(e.as_i32() as i64);
    }
    if let Err(e) = vp.inode.get_write_access() { return -(e as i64); }
    let rc = do_truncate(&vp.inode, vp.mnt_id, len, 0, cred);
    vp.inode.put_write_access();
    rc
}

/// `ftruncate(2)` descriptor form.
/// Only a regular file opened for WRITING is truncatable through an fd; every
/// other combination is `EINVAL` (never `EISDIR`, unlike the path form). An
/// append-only inode is `EPERM` ahead of the mount read-only gate. Timestamps
/// are updated (`ATTR_MTIME | ATTR_CTIME`), which the path form leaves to
/// `notify_change`'s implicit `ctime` stamp. # C: O(1)
pub fn do_ftruncate(file: &File, len: u64, cred: &vfs::Cred) -> i64 {
    if !matches!(file.inode().file_type(), FileType::Regular)
        || !file.f_mode().contains(vfs::Fmode::WRITE) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if file.inode().i_flags() & vfs::S_APPEND != 0 {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // `do_ftruncate` reaches `do_truncate` through the same `get_write_access`
    // gate as the path form — an fd opened for write on a file that later got
    // executed must still refuse.
    if let Err(e) = crate::inotify::check_truncate_perm(file.inode(), len) {
        return -(e.as_i32() as i64);
    }
    if let Err(e) = file.inode().get_write_access() { return -(e as i64); }
    let rc = do_truncate(file.inode(), file.mnt_id(), len, vfs::ATTR_MTIME | vfs::ATTR_CTIME, cred);
    file.inode().put_write_access();
    rc
}
