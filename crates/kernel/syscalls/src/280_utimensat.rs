// 280 utimensat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::utime_common::{now_ns, resolve_target, AT_FDCWD};

const UTIME_NOW:  i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

/// Decode one `timespec` slot. `None` = UTIME_OMIT (leave alone);
/// `Some((ns, specific))` where `specific` distinguishes a real time
/// (owner/CAP_FOWNER required) from UTIME_NOW / NULL (MAY_WRITE suffices).
/// # C: O(1)
fn read_user_ns_pair(p: u64, idx: usize, now: u64) -> Result<Option<(u64, bool)>, i64> {
    // Linux: each timespec is 16 bytes (sec + nsec, i64 each).
    let off = (idx * 16) as u64;
    if p.checked_add(off + 16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p+off+16 validated < USER_VA_END; CPL=0 reads the timespec pair (i64 sec, i64 nsec) through caller's AS.
    unsafe {
        let sec  = core::ptr::read_volatile((p + off)     as *const i64);
        let nsec = core::ptr::read_volatile((p + off + 8) as *const i64);
        if nsec == UTIME_OMIT { return Ok(None); }
        if nsec == UTIME_NOW  { return Ok(Some((now, false))); }
        if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
        Ok(Some((((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64)), true)))
    }
}

/// `sys_utimensat(dirfd, path, times[2], flags)` — slot 280.
/// `times == NULL` ⇒ both atime and mtime = now. Each slot may be UTIME_NOW,
/// UTIME_OMIT, or a real timespec. Routes through `notify_change`: setting a
/// specific time needs owner/CAP_FOWNER (EPERM), setting "now"/NULL needs
/// MAY_WRITE (EACCES); EROFS on a read-only mount. `AT_SYMLINK_NOFOLLOW`
/// operates on the symlink itself (U2). # C: O(N_path)
pub fn sys_utimensat(args: &SyscallArgs) -> i64 {
    let dirfd     = args.a0 as i32;
    let path_ptr  = args.a1;
    let times_ptr = args.a2;
    let flags     = args.a3;
    let _ = AT_FDCWD;
    if flags & !AT_SYMLINK_NOFOLLOW != 0 { return -(Errno::Einval.as_i32() as i64); }
    let no_follow = flags & AT_SYMLINK_NOFOLLOW != 0;
    let (inode, mnt_id) = match resolve_target(dirfd, path_ptr, no_follow) {
        Ok(t) => t, Err(rv) => return rv,
    };
    let now = now_ns();
    let mut ia = vfs::Iattr { ctime_ns: now, ..Default::default() };
    if times_ptr == 0 {
        ia.valid |= vfs::ATTR_ATIME | vfs::ATTR_MTIME;
        ia.atime_ns = now; ia.mtime_ns = now;
    } else {
        let a = match read_user_ns_pair(times_ptr, 0, now) { Ok(v) => v, Err(rv) => return rv };
        let m = match read_user_ns_pair(times_ptr, 1, now) { Ok(v) => v, Err(rv) => return rv };
        if let Some((t, spec)) = a {
            ia.valid |= vfs::ATTR_ATIME;
            if spec { ia.valid |= vfs::ATTR_ATIME_SET; }
            ia.atime_ns = t;
        }
        if let Some((t, spec)) = m {
            ia.valid |= vfs::ATTR_MTIME;
            if spec { ia.valid |= vfs::ATTR_MTIME_SET; }
            ia.mtime_ns = t;
        }
        // Both UTIME_OMIT ⇒ no-op success (Linux returns before any check).
        if ia.valid & (vfs::ATTR_ATIME | vfs::ATTR_MTIME) == 0 { return 0; }
    }
    crate::perms_common::notify_change(&inode, mnt_id, ia)
}
