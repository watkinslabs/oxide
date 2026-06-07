// 280 utimensat — one syscall, one file (docs/53 §0). Moved verbatim from utime.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::utime_common::{now_ns, resolve_inode, AT_FDCWD};

const UTIME_NOW:  i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

/// # C: O(1)
fn read_user_ns_pair(p: u64, idx: usize, now: u64) -> Result<Option<u64>, i64> {
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
        if nsec == UTIME_NOW  { return Ok(Some(now)); }
        if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
        Ok(Some((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64)))
    }
}

/// `sys_utimensat(dirfd, path, times[2], flags)` — slot 280.
/// `times == NULL` ⇒ both atime and mtime = now.
/// Each slot may be UTIME_NOW (use now_ns), UTIME_OMIT (don't change),
/// or a real timespec.
/// # C: O(N_path)
pub fn sys_utimensat(args: &SyscallArgs) -> i64 {
    let dirfd    = args.a0 as i32;
    let path_ptr = args.a1;
    let times_ptr = args.a2;
    let _flags   = args.a3;
    let _ = AT_FDCWD;
    let inode = match resolve_inode(dirfd, path_ptr) {
        Ok(i) => i, Err(rv) => return rv,
    };
    let now = now_ns();
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now))
    } else {
        let a = match read_user_ns_pair(times_ptr, 0, now) { Ok(v) => v, Err(rv) => return rv };
        let m = match read_user_ns_pair(times_ptr, 1, now) { Ok(v) => v, Err(rv) => return rv };
        (a, m)
    };
    if inode.set_times(atime, mtime, now).is_err() {
        vfs::inode_times::set(&inode, atime, mtime, now);
    }
    0
}
