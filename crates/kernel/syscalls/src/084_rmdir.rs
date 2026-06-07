// 084 rmdir — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared do_rmdir core (also used by 263_unlinkat AT_REMOVEDIR).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, errno_from_vfs, resolve_parent};

/// Single rmdir core — both `rmdir(2)` (slot 84, x86 legacy) and
/// `unlinkat(…, AT_REMOVEDIR)` (the only form aarch64 has) delegate
/// here so the two ABI entry points can never diverge (Linux routes
/// both through `do_rmdirat`). `p` is the resolved absolute path;
/// the caller has already run the landlock REMOVE_DIR check.
/// Pseudo-fs dirs (cgroupfs, …) own their rmdir; ext4 dirs go to the
/// ext4 backend; everything else is read-only.
/// # C: O(1)
pub(crate) fn do_rmdir(p: &str) -> i64 {
    let (pino, name) = match resolve_parent(p) { Ok(x) => x, Err(rv) => return rv };
    match pino.rmdir(&name) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}

/// `rmdir(path)` slot 84 (x86 legacy; absent on aarch64).
/// # C: O(1)
pub fn sys_rmdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::REMOVE_DIR) { return rv; }
    do_rmdir(&p)
}
