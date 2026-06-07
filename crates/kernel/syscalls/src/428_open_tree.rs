// 428 open_tree — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_open_tree(dirfd, path, flags)` — slot 428. `OPEN_TREE_CLONE`
/// detaches a CLONE of the mount at `path` into an fd (the source for a
/// later `move_mount`); without it, returns an O_PATH-like fd referring to
/// the path. `OPEN_TREE_CLOEXEC = O_CLOEXEC`. systemd uses the clone form
/// for `RootDirectory=`/sandbox setup.
/// # C: O(N_mounts)
pub fn sys_open_tree(args: &SyscallArgs) -> i64 {
    const OPEN_TREE_CLONE:   u64 = 1;
    const OPEN_TREE_CLOEXEC: u64 = 0o2_000_000;     // O_CLOEXEC
    let path = match read_cstr(args.a1, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let abs = crate::pathresolve::resolve_cwd(&path);
    let abs = if abs.len() > 1 { abs.trim_end_matches('/').to_string() } else { abs };
    let cloexec = (args.a2 & OPEN_TREE_CLOEXEC) != 0;
    if (args.a2 & OPEN_TREE_CLONE) != 0 {
        // Capture the mount rooted at `abs` (fs + root inode) into a
        // detached clone object.
        let (mnt, _) = match vfs::mount::resolve_mount(&abs) {
            Some(m) => m, None => return -(Errno::Enoent.as_i32() as i64),
        };
        let root = match mnt.root.clone().or_else(|| mnt.fs.root()) {
            Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
        };
        let mo = MountObjectInode::new_clone(mnt.fs.clone(), root) as InodeRef;
        return install_fd(mo, "open_tree", cloexec);
    }
    // Non-clone: an fd referring to the path's inode (O_PATH-ish).
    match crate::pathresolve::resolve(&abs, false) {
        Some(i) => install_fd(i, "open_tree", cloexec),
        None    => -(Errno::Enoent.as_i32() as i64),
    }
}
