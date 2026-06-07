// 087 unlink — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, errno_from_vfs, resolve_parent};

/// `unlink(path)` slot 87.
/// # C: O(N parent entries)
pub fn sys_unlink(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::REMOVE_FILE) { return rv; }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.unlink_child(&name) { Ok(()) => 0, Err(e) => errno_from_vfs(e) }
}
