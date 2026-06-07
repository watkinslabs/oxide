// 429 move_mount — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_move_mount(from_dirfd, from_path, to_dirfd, to_path, flags)` —
/// slot 429. Two modes: (a) attach a DETACHED mount produced by `fsmount`
/// (from_dirfd is its fd, from_path empty via MOVE_MOUNT_F_EMPTY_PATH) at
/// `to_path`; (b) relocate an EXISTING mount at `from_path` to `to_path`.
/// # C: O(N_mounts)
pub fn sys_move_mount(args: &SyscallArgs) -> i64 {
    let from_fd = args.a0 as i32;
    let from_path = read_cstr(args.a1, 256).unwrap_or_default();
    let to_path = match read_cstr(args.a3, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let target = crate::pathresolve::resolve_cwd(&to_path);
    let target = if target.len() > 1 { target.trim_end_matches('/').to_string() } else { target };

    // Mode (a): from_fd refers to a detached fsmount object.
    if from_path.is_empty() {
        let inode = match fd_inode(from_fd) {
            Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        if let Some(mo) = inode.as_any().and_then(|a| a.downcast_ref::<MountObjectInode>()) {
            // open_tree clone: bind the captured (fs, root) at the target.
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                let _ = vfs::mount::register_bind(&target, fs.clone(), root.clone());
                return 0;
            }
            return attach_mount(&mo.fstype, &target);
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    // Mode (b): relocate an existing mount.
    let from = crate::pathresolve::resolve_cwd(&from_path);
    let from = if from.len() > 1 { from.trim_end_matches('/').to_string() } else { from };
    match vfs::mount::move_mount(&from, &target) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}

/// Materialise `fstype` as a mount at `target` (the new-API counterpart of
/// `sys_mount`'s fstype switch).
/// # C: O(N_mounts)
fn attach_mount(fstype: &str, target: &str) -> i64 {
    match fstype {
        "tmpfs" | "ramfs" => {
            let root: InodeRef = Arc::new(::fs::tmpfs::TmpfsRootInode::new(target.to_string()));
            let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(::fs::tmpfs::TmpfsFs);
            let _ = vfs::mount::register_bind(target, fs, root);
            0
        }
        "cgroup2" => { cgroup::mount_root(); 0 }
        // proc/sysfs/devtmpfs/devpts are already present at their canonical
        // mount points; admit so the new-API probe path doesn't error.
        "proc" | "sysfs" | "devtmpfs" | "devpts" => 0,
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}
