// 094 lchown — one syscall, one file (docs/53 §0). Linux `fs/open.c`
// `SYSCALL_DEFINE3(lchown)` is `do_fchownat(AT_FDCWD, name, uid, gid,
// AT_SYMLINK_NOFOLLOW)`: the FINAL component is NOT followed, so a symlink
// path changes the LINK's ownership, never its target's. Slot 94 previously
// shared `092_chown`'s follow=true resolver, which silently chowned the
// target — the exact bug `lchown(2)` exists to avoid.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_path_mnt, do_chown, AT_FDCWD};

/// `sys_lchown(path, uid, gid)` — slot 94. `AT_SYMLINK_NOFOLLOW` semantics:
/// operate on the symlink itself. `(uid_t)-1` leaves that id unchanged; the
/// setuid/setgid strip + CAP_CHOWN ladder are `do_chown`'s (shared with
/// chown/fchown/fchownat).
/// # C: O(N_path)
pub fn sys_lchown(args: &SyscallArgs) -> i64 {
    let (inode, mnt_id) = match resolve_path_mnt(AT_FDCWD, args.a0, false) {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    let rc = do_chown(&inode, mnt_id, args.a1 as u32, args.a2 as u32);
    // FAN_ATTRIB / IN_ATTRIB on a successful ownership change (Linux fsnotify_change).
    if rc == 0 { ::fs::inotify::fire_attrib(&inode); }
    rc
}
