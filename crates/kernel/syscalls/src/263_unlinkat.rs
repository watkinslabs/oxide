// 263 unlinkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::read_user_path;

const AT_REMOVEDIR: u32 = 0x200;

/// `unlinkat(dirfd, path, flags)` slot 263. Honours `AT_REMOVEDIR`
/// (→ rmdir) and resolves `path` against `dirfd`.
/// # C: O(N parent entries)
pub fn sys_unlinkat(args: &SyscallArgs) -> i64 {
    let flags = args.a2 as u32;
    // Unknown flag bits → EINVAL (Linux do_unlinkat: only AT_REMOVEDIR valid).
    if flags & !AT_REMOVEDIR != 0 { return -(Errno::Einval.as_i32() as i64); }
    // X4: EFAULT(bad ptr) / ENOENT(empty) / ENAMETOOLONG, not EINVAL.
    let raw = match read_user_path(args.a1) {
        Ok(s) => s, Err(rv) => return rv,
    };
    // do_rmdirat: AT_REMOVEDIR with a `.`/`..` final component → EINVAL/ENOTEMPTY
    // (LAST_DOT/LAST_DOTDOT). Plain unlink of `.`/`..` is EISDIR via the backend.
    if (flags & AT_REMOVEDIR) != 0 {
        if let Some(rv) = crate::namei_common::rmdir_dot_errno(&raw) { return rv; }
    }
    // AT_REMOVEDIR is rmdir — delegate to the shared core so the
    // legacy rmdir(2) and the *at form (the only one aarch64 has)
    // stay identical. Without this, cgroup/pseudo-fs rmdir worked on
    // x86 (via sys_rmdir) but returned EROFS on arm.
    if (flags & AT_REMOVEDIR) != 0 {
        return crate::s084_rmdir::do_rmdir_at(args.a0 as i32, &raw);
    }
    crate::s087_unlink::unlink_at(args.a0 as i32, &raw)
}
