// 155 pivot_root — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::read_user_cstr_owned;

/// `sys_pivot_root(new_root, put_old)` — slot 155. Makes the mount at
/// `new_root` the namespace root and relocates the old root tree under
/// `put_old` (`docs/16§6`). Requires CAP_SYS_ADMIN. Both paths absolute.
/// # C: O(N_mounts)
pub fn sys_pivot_root(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let new_root = match read_user_cstr_owned(args.a0, 256) { Ok(s) => s, Err(rv) => return rv };
    let put_old  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    if !new_root.starts_with('/') || !put_old.starts_with('/') {
        return -(Errno::Einval.as_i32() as i64);
    }
    let nr = if new_root.len() > 1 { new_root.trim_end_matches('/') } else { &new_root };
    let po = if put_old.len() > 1 { put_old.trim_end_matches('/') } else { &put_old };
    match vfs::mount::pivot_root(nr, po) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
