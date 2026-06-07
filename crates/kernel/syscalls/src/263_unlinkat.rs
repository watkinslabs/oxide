// 263 unlinkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, errno_from_vfs, resolve_parent};

const AT_REMOVEDIR: u32 = 0x200;

/// `unlinkat(dirfd, path, flags)` slot 263. We currently honour
/// the `AT_REMOVEDIR` flag → rmdir; ignore dirfd (no per-fd
/// directory state yet — paths are absolute or cwd-relative).
/// # C: O(N parent entries)
pub fn sys_unlinkat(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a1) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: resolve against the real dirfd (a0).
    let p = match crate::pathresolve::resolve_at(args.a0 as i32, &raw) {
        Some(rp) => rp, None => resolve(&raw).unwrap_or(raw),
    };
    let flags = args.a2 as u32;
    let op = if (flags & AT_REMOVEDIR) != 0 {
        ::security::landlock::access::REMOVE_DIR
    } else {
        ::security::landlock::access::REMOVE_FILE
    };
    if let Err(rv) = crate::landlock::check(&p, op) { return rv; }
    // AT_REMOVEDIR is rmdir — delegate to the shared core so the
    // legacy rmdir(2) and the *at form (the only one aarch64 has)
    // stay identical. Without this, cgroup/pseudo-fs rmdir worked on
    // x86 (via sys_rmdir) but returned EROFS on arm.
    if (flags & AT_REMOVEDIR) != 0 {
        return crate::s084_rmdir::do_rmdir(&p);
    }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.unlink_child(&name) { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}
