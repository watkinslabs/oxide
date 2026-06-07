// 090 chmod — one syscall, one file (docs/53 §0).
// v1 stores the mode overlay in `inode_times` so statx surfaces it back
// to userspace when the Inode impl lacks native perm storage.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perms_common::{resolve_path_inode, now_ns, AT_FDCWD};

/// `sys_chmod(path, mode)` — slot 90.
/// # C: O(N_path)
pub fn sys_chmod(args: &SyscallArgs) -> i64 {
    // F132: AF_UNIX socket paths don't have backing filesystem
    // entries in v1 — the UnixRegistry tracks them by string key.
    // Linux's bind(AF_UNIX) materialises a socket-type inode at the
    // path; chmod on it succeeds. Until we materialise socket-type
    // tmpfs inodes, accept chmod on any known UnixRegistry path
    // so dhcpcd's control-socket setup (bind → chmod → listen)
    // doesn't bail at the chmod step.
    // SAFETY: read_user_cstr does its own ptr-range + bounded-read validation.
    if let Some(bytes) = unsafe { devfs::read_user_cstr(args.a0, 108) } {
        if let Ok(s) = core::str::from_utf8(bytes) {
            if net::sock::UNIX_REGISTRY.is_bound(s) { return 0; }
        }
    }
    let inode = match resolve_path_inode(AT_FDCWD, args.a0, true) { Ok(i) => i, Err(rv) => return rv };
    let m = args.a1 as u16;
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(&inode, m, now_ns()); }
    0
}
