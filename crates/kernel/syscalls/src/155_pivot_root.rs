// 155 pivot_root — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::read_user_cstr_owned;

/// `sys_pivot_root(new_root, put_old)` — slot 155. Makes the mount at
/// `new_root` the namespace root and relocates the old root tree under
/// `put_old` (`docs/16§6`). Requires CAP_SYS_ADMIN. Paths are resolved like
/// normal Linux pathnames, so relative arguments are interpreted against cwd.
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
    let nr = crate::pathresolve::resolve_cwd(&new_root);
    let po = crate::pathresolve::resolve_cwd(&put_old);
    let nr = if nr.len() > 1 { nr.trim_end_matches('/').to_string() } else { nr };
    let po = if po.len() > 1 { po.trim_end_matches('/').to_string() } else { po };
    // The two namei walks pivot_root(2) hands the engine: new_root + put_old
    // mountpoint dentries (Linux `struct path.dentry`). The SAME `Arc`s the
    // engine compares by identity (the `pivot_root(".",".")` stacking case).
    let nr_d = match crate::pathresolve::mount_dentry(&nr) {
        Some(d) => d, None => return -(Errno::Einval.as_i32() as i64),
    };
    let po_d = match crate::pathresolve::mount_dentry(&po) {
        Some(d) => d, None => return -(Errno::Einval.as_i32() as i64),
    };
    match vfs::mount::pivot_root(&nr_d, &po_d) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
