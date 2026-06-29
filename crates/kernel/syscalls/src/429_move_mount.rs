// 429 move_mount — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

/// `sys_move_mount(from_dirfd, from_path, to_dirfd, to_path, flags)` —
/// slot 429. Two modes: (a) attach a DETACHED mount produced by `fsmount`
/// (from_dirfd is its fd, from_path empty via MOVE_MOUNT_F_EMPTY_PATH) at
/// `to_path`; (b) relocate an EXISTING mount at `from_path` to `to_path`.
/// # C: O(N_mounts)
pub fn sys_move_mount(args: &SyscallArgs) -> i64 {
    let rv = sys_move_mount_impl(args);
    #[cfg(feature = "debug-mount")]
    {
        let to = read_cstr(args.a3, 256).unwrap_or_default();
        let from = read_cstr(args.a1, 256).unwrap_or_default();
        let mut tag = alloc::string::String::from(to.as_str());
        tag.push_str(" from="); tag.push_str(&from);
        crate::mount_common::mnt_log("move_mount", &tag, rv);
    }
    rv
}

fn sys_move_mount_impl(args: &SyscallArgs) -> i64 {
    let from_fd = args.a0 as i32;
    let from_path = read_cstr(args.a1, 256).unwrap_or_default();
    let to_path = match read_cstr(args.a3, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let target = match crate::pathresolve::resolve_at_result(args.a2 as i32, &to_path) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let target = if target.len() > 1 { target.trim_end_matches('/').to_string() } else { target };

    #[cfg(feature = "debug-boot")]
    if target.contains("credentials") {
        let ns = sched::live::current().map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
        klog::write_raw(b"[cred move_mount] ns="); klog::write_dec_u64(ns);
        klog::write_raw(b" from="); klog::write_raw(from_path.as_bytes());
        klog::write_raw(b" to="); klog::write_raw(target.as_bytes());
        klog::write_raw(b"\n");
    }
    // The single namei walk move_mount(2) hands the engine: the target
    // mountpoint dentry (Linux `struct path.dentry`).
    let target_d = match crate::pathresolve::mount_dentry(&target) {
        Some(d) => d, None => return -(Errno::Enoent.as_i32() as i64),
    };
    // Mode (a): from_fd refers to a detached fsmount object.
    if from_path.is_empty() {
        let inode = match fd_inode(from_fd) {
            Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        if let Some(mo) = inode.as_any().and_then(|a| a.downcast_ref::<MountObjectInode>()) {
            // open_tree clone: bind the captured (fs, root) at the target.
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                let _ = vfs::mount::register_bind(Some(target_d.clone()), fs.clone(), root.clone());
                return 0;
            }
            return mount_fstype(&mo.source, &mo.fstype, &target, &target_d);
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    // Mode (b): relocate an existing mount.
    let from = match crate::pathresolve::resolve_at_result(from_fd, &from_path) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let from = if from.len() > 1 { from.trim_end_matches('/').to_string() } else { from };
    let from_d = match crate::pathresolve::mount_dentry(&from) {
        Some(d) => d, None => return -(Errno::Einval.as_i32() as i64),
    };
    match vfs::mount::move_mount(&from_d, &target_d) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
