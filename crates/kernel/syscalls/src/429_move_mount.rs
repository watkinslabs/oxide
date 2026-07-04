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
    // TEMP (D24, debug-mnt): mount-creating syscall ENTRY trace — this is where
    // an open_tree-cloned subtree is spliced under the sandbox root (10/11).
    #[cfg(feature = "debug-mount")]
    {
        let from = read_cstr(args.a1, 256).unwrap_or_default();
        let to = read_cstr(args.a3, 256).unwrap_or_default();
        klog::write_raw(b"[MNTCREATE] syscall=move_mount flags=0x");
        klog::write_hex_u64(args.a4);
        klog::write_raw(b" recursive=false source="); klog::write_raw(from.as_bytes());
        klog::write_raw(b" target="); klog::write_raw(to.as_bytes());
        klog::write_raw(b"\n");
    }
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
            // D24 Stage 1a: an open_tree-cloned SUBTREE → splice it under the
            // target HASH-ONLY (adds the (clone_root,/proc) etc. strict-hash
            // entries; the legacy `mounted_mounts` walk oracle is untouched, so
            // boot stays green this stage). TAKE it so the inode's Drop does not
            // also release the now-committed clones.
            if let Some(tree) = mo.detached_tree.lock().take() {
                let _ = vfs::mount::commit_tree_hashonly(tree, &target_d);
                return 0;
            }
            // open_tree clone (legacy non-recursive): bind the captured (fs, root).
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                let _ = vfs::mount::register_bind(Some(target_d.clone()), fs.clone(), root.clone());
                return 0;
            }
            // CONVERTED: graft the already-realized SB (Linux do_move_mount over a
            // fsmount object), then deliver mount propagation to the destination
            // peer group — the same `register*`+`propagate_mount` outcome the
            // `mount_fstype` fallback produces. [D51] The `fsmount(2)` MOUNT_ATTR_*
            // request stored on the object (`mnt_attrs`) is mapped into the MNT_*
            // option space and stamped on the new mount BEFORE it goes live, so a
            // following `propagate_mount` peer-copy inherits it (clone_mnt copies
            // src.flags); the prior path dropped these bits.
            if let Some((sb, _root)) = mo.realized.as_ref() {
                let mnt_flags = vfs::mount::mount_attr_to_mnt(
                    mo.mnt_attrs.load(core::sync::atomic::Ordering::Acquire));
                // Parent = the mount the target-dir walk crossed into, not a
                // re-derivation from the (bind-shared) mountpoint dentry. systemd
                // creates the sandbox apivfs at /run/systemd/namespace-X after
                // rbinding / onto /run/systemd/mount-rootfs, so parent_by_dentry
                // is ambiguous; the walked mnt_id places it under the real /run.
                let phint = crate::pathresolve::resolve_path(&target, false).map(|p| p.mnt_id);
                return match vfs::mount::attach_sb_with_flags_at(Some(target_d.clone()), sb.clone(), mnt_flags, phint) {
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
    // Destination mount id from the walk: disambiguates a `to` sitting in a bind
    // mount (shared dentries defeat `parent_by_dentry`). Falls back to `target_d`.
    let to_mnt = crate::pathresolve::resolve_path(&target, false).map(|p| p.mnt_id);
    match vfs::mount::move_mount_by_id_to(from_vp.mnt_id, to_mnt, &target_d) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
