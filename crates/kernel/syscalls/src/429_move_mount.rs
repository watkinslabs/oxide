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
    if let Some(rv) = require_sys_admin() { return rv; }  // Linux may_mount (D49)
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
        if let Some(mo) = inode.private::<MountObjectInode>() {
            // open_tree clone: bind the captured (fs, root) at the target.
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                let _ = vfs::mount::register_bind(Some(target_d.clone()), fs.clone(), root.clone());
                return 0;
            }
            // CONVERTED: graft the already-realized SB (Linux do_move_mount over a
            // fsmount object), then deliver mount propagation to the destination
            // peer group — the same `register*`+`propagate_mount` outcome the
            // `mount_fstype` fallback produces. `mnt_attrs` are NOT applied here:
            // the prior path dropped them, so applying would change the booted
            // mount-table state (deferred behind boot-verify, D51 PARTIAL).
            if let Some((sb, _root)) = mo.realized.as_ref() {
                return match vfs::mount::attach_sb(Some(target_d.clone()), sb.clone()) {
                    Ok(()) => { let _ = vfs::mount::propagate_mount(&target_d); 0 }
                    Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                    Err(e) => crate::namei_common::errno_from_vfs(e),
                };
            }
            // LEGACY: materialise-by-fstype at attach (byte-identical fallback).
            return mount_fstype(&mo.source, &mo.fstype, &target, &target_d);
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    // Mode (b): relocate an existing mount.
    let from = match crate::pathresolve::resolve_at_result(from_fd, &from_path) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let from = if from.len() > 1 { from.trim_end_matches('/').to_string() } else { from };
    // Source mount = the `mnt_id` the walk crossed into (Linux `path->mnt`), not
    // a re-derived dentry (which resolves onto the moved mount's shared root).
    let from_vp = match crate::pathresolve::resolve_path(&from, false) {
        Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
    };
    match vfs::mount::move_mount_by_id(from_vp.mnt_id, &target_d) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
