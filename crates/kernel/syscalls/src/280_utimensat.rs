// 280 utimensat — one syscall, one file (docs/53 §0). Thin shim: copy in,
// call the ungated decisions in `utimensat_abi`, resolve, apply.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::utime_common::{now, read_timespec_pair, resolve_target};
use crate::utimensat_abi::{both_omit, check_path_form_flags, resolve_pair, utimensat_iattr};
use crate::utimes_abi::iattr_touch;

/// `sys_utimensat(dirfd, path, times[2], flags)` — slot 280.
/// `times == NULL` ⇒ both atime and mtime = now. Each slot may be UTIME_NOW,
/// UTIME_OMIT, or a real timespec — including a PRE-1970 one, which Linux
/// accepts because `nsec_valid` (`fs/utimes.c:13-19`) checks `tv_nsec` alone
/// and never bounds `tv_sec`. Routes through `notify_change`: setting a
/// specific time needs owner/CAP_FOWNER (EPERM), setting "now"/NULL needs
/// MAY_WRITE (EACCES); EROFS on a read-only mount. `AT_SYMLINK_NOFOLLOW`
/// operates on the symlink itself (U2); `AT_EMPTY_PATH` stamps the dirfd.
///
/// Ladder order is `SYSCALL_DEFINE4(utimensat)`'s (`fs/utimes.c:141-160`):
/// copy in (EFAULT) → both-UTIME_OMIT no-op → flag check → lookup →
/// `nsec_valid`. The both-OMIT case therefore succeeds without the path being
/// touched at all ("Nothing to do, we must not even check the path").
/// # C: O(N_path)
pub fn sys_utimensat(args: &SyscallArgs) -> i64 {
    let dirfd     = args.a0 as i32;
    let path_ptr  = args.a1;
    let times_ptr = args.a2;
    let flags     = args.a3;
    let raw = if times_ptr == 0 {
        None
    } else {
        match read_timespec_pair(times_ptr) {
            Ok(t) => { if both_omit(&t) { return 0; } Some(t) }
            Err(rv) => return rv,
        }
    };
    // `do_utimes_fd` takes no flags at all (`fs/utimes.c:110-111`): the fd form
    // rejects even AT_SYMLINK_NOFOLLOW, which is legal on the path form.
    let fd_form = crate::utimes_abi::utimes_target(dirfd, path_ptr == 0)
        != crate::utimes_abi::UtimesTarget::Path;
    let gate = if fd_form { crate::utimes_abi::check_fd_form_flags(flags) }
               else       { check_path_form_flags(flags) };
    if let Err(e) = gate { return -(e.as_i32() as i64); }
    let no_follow = flags & syscall::at::AT_SYMLINK_NOFOLLOW as u64 != 0;
    let empty     = flags & syscall::at::AT_EMPTY_PATH as u64 != 0;
    let (inode, mnt_id) = match resolve_target(dirfd, path_ptr, no_follow, empty) {
        Ok(t) => t, Err(rv) => return rv,
    };
    let now = now();
    let ia = match raw {
        None => iattr_touch(now),
        Some(t) => {
            let (a, m) = match resolve_pair(&t) {
                Ok(v) => v, Err(e) => return -(e.as_i32() as i64),
            };
            match utimensat_iattr(a, m, now) { Some(ia) => ia, None => return 0 }
        }
    };
    crate::perms_common::notify_change(&inode, mnt_id, ia)
}
