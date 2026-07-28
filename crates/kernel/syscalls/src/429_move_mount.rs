// 429 move_mount — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

fn trim_move_path(raw: &str) -> Result<&str, i64> {
    if raw.is_empty() { return Err(-(Errno::Enoent.as_i32() as i64)); }
    let trimmed = if raw.len() > 1 { raw.trim_end_matches('/') } else { raw };
    if trimmed.is_empty() { Ok("/") } else { Ok(trimmed) }
}

fn resolve_move_target_at(dirfd: i32, raw: &str) -> Result<(vfs::MountTarget, alloc::string::String), i64> {
    let raw = trim_move_path(raw)?;
    if let Some(p) = crate::pathresolve::procfd_path(raw) {
        let display = vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry);
        let target = vfs::mount_target_from_resolved_path(p);
        return Ok((target, display));
    }
    if raw == "/" {
        let p = crate::pathresolve::resolve_at_path(dirfd, raw, vfs::LookupFlags::default())?;
        let target = vfs::MountTarget { parent: p.clone(), mountpoint: p.dentry.clone() };
        let display = vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry);
        return Ok((target, display));
    }
    let parent = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    if parent.last_type() != vfs::LastType::Norm { return Err(-(Errno::Einval.as_i32() as i64)); }
    let name = parent.last_component.as_deref().ok_or(-(Errno::Einval.as_i32() as i64))?;
    let pi = parent.dentry.inode().ok_or(-(Errno::Enoent.as_i32() as i64))?;
    let mountpoint = match vfs::d_lookup(&parent.dentry, name) {
        Some(d) if !d.is_negative() => d,
        _ => {
            let ci = pi.lookup(name).map_err(crate::namei_common::errno_from_vfs)?;
            vfs::d_add(&parent.dentry, name, ci)
        }
    };
    let display = vfs::mount::render_path_for_mount(parent.mnt_id, &mountpoint);
    Ok((vfs::MountTarget { parent, mountpoint }, display))
}

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
        if let (Ok(from), Ok(to)) = (read_path_allow_empty(args.a1), read_path_allow_empty(args.a3)) {
            klog::write_raw(b"[MNTCREATE] syscall=move_mount flags=0x");
            klog::write_hex_u64(args.a4);
            klog::write_raw(b" recursive=false source="); klog::write_raw(from.as_bytes());
            klog::write_raw(b" target="); klog::write_raw(to.as_bytes());
            klog::write_raw(b"\n");
        }
    }
    let rv = sys_move_mount_impl(args);
    #[cfg(feature = "debug-mount")]
    {
        if let (Ok(to), Ok(from)) = (read_path_allow_empty(args.a3), read_path_allow_empty(args.a1)) {
            let mut tag = alloc::string::String::from(to.as_str());
            tag.push_str(" from="); tag.push_str(&from);
            crate::mount_common::mnt_log("move_mount", &tag, rv);
        }
    }
    rv
}

fn sys_move_mount_impl(args: &SyscallArgs) -> i64 {
    if let Some(rv) = may_mount_or_eperm() { return rv; }  // Linux may_mount (D49)
    let from_fd = args.a0 as i32;
    let from_path = match read_path_allow_empty(args.a1) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let to_path = match read_path_allow_empty(args.a3) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let (target_mt, target) = match resolve_move_target_at(args.a2 as i32, &to_path) {
        Ok(t) => t, Err(rv) => return rv,
    };
    let target_d = target_mt.mountpoint.clone();
    let target_mnt = target_mt.parent.mnt_id;

    #[cfg(feature = "debug-boot")]
    if target.contains("credentials") {
        let ns = sched::live::current().and_then(sched::Task::mount_namespace_id).unwrap_or(0);
        klog::write_raw(b"[cred move_mount] ns="); klog::write_dec_u64(ns);
        klog::write_raw(b" from="); klog::write_raw(from_path.as_bytes());
        klog::write_raw(b" to="); klog::write_raw(target.as_bytes());
        klog::write_raw(b"\n");
    }
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
                let _ = vfs::mount::commit_tree_hashonly_at(tree, &target_d, target_mnt);
                return 0;
            }
            // open_tree clone (legacy non-recursive): bind the captured (fs, root).
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                let _ = vfs::mount::register_bind_at(Some(target_d.clone()), fs.clone(), root.clone(), Some(target_mnt));
                return 0;
            }
            // Graft the already-realized SB (Linux do_move_mount over a
            // fsmount object), then deliver mount propagation to the destination
            // peer group. [D51] The `fsmount(2)` MOUNT_ATTR_* request stored on
            // the object (`mnt_attrs`) is mapped into the MNT_* option space and
            // stamped on the new mount BEFORE it goes live, so a following
            // `propagate_mount` peer-copy inherits it (clone_mnt copies src.flags).
            if let Some((sb, _root)) = mo.realized.as_ref() {
                let mnt_flags = vfs::mount::mount_attr_to_mnt(
                    mo.mnt_attrs.load(core::sync::atomic::Ordering::Acquire));
                // Parent = the mount the target-dir walk crossed into, not a
                // re-derivation from the (bind-shared) mountpoint dentry. systemd
                // creates the sandbox apivfs at /run/systemd/namespace-X after
                // rbinding / onto /run/systemd/mount-rootfs, so parent_by_dentry
                // is ambiguous; the walked mnt_id places it under the real /run.
                return match vfs::mount::attach_sb_with_flags_at(Some(target_d.clone()), sb.clone(), mnt_flags, Some(target_mnt)) {
                    Ok(()) => { let _ = vfs::mount::propagate_mount(&target_d); 0 }
                    Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                    Err(e) => crate::namei_common::errno_from_vfs(e),
                };
            }
            return -(Errno::Einval.as_i32() as i64);
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    // Mode (b): relocate an existing mount.
    // Source mount = the `mnt_id` the walk crossed into (Linux `path->mnt`), not
    // a re-derived dentry (which resolves onto the moved mount's shared root).
    let from_vp = match crate::pathresolve::resolve_at_path(from_fd, &from_path, vfs::LookupFlags::default()) {
        Ok(p) => p, Err(rv) => return rv,
    };
    // Destination mount id from the walk: disambiguates a `to` sitting in a bind
    // mount (shared dentries defeat `parent_by_dentry`). Falls back to `target_d`.
    match vfs::mount::move_mount_by_id_to_rendered(from_vp.mnt_id, Some(target_mnt), &target_d, target) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
