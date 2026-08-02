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

/// `LookupFlags` for one `move_mount(2)` pathname. `move_mount` is the one
/// member of the `*at` family that walks WITHOUT `LOOKUP_FOLLOW` by default —
/// symlinks and automounts are opted into per side by
/// `MOVE_MOUNT_{F,T}_SYMLINKS` / `_AUTOMOUNTS`. # C: O(1)
fn side_lookup(side: crate::move_mount_policy::Side, parent: bool) -> vfs::LookupFlags {
    vfs::LookupFlags {
        parent,
        empty: side.empty,
        follow: side.follow,
        no_follow_final: !side.follow,
        no_automount: !side.automount,
        ..Default::default()
    }
}

fn resolve_move_target_at(dirfd: i32, raw: &str, side: crate::move_mount_policy::Side)
    -> Result<(vfs::MountTarget, alloc::string::String), i64> {
    let raw = trim_move_path(raw)?;
    if let Some(p) = crate::pathresolve::procfd_path(raw) {
        let display = vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry);
        let target = vfs::mount_target_from_resolved_path(p);
        return Ok((target, display));
    }
    if raw == "/" {
        let p = crate::pathresolve::resolve_at_path(dirfd, raw, side_lookup(side, false))?;
        let target = vfs::MountTarget { parent: p.clone(), mountpoint: p.dentry.clone() };
        let display = vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry);
        return Ok((target, display));
    }
    let parent = crate::pathresolve::resolve_parent_at_flags(dirfd, raw, side_lookup(side, true))?;
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

/// Linux `getname_maybe_null(name, AT_EMPTY_PATH)` reduced to a string: an
/// empty result means "operate on the descriptor". Without `empty_ok` a NULL
/// pointer is `EFAULT` and an empty string stays empty only long enough for
/// the caller's `ENOENT`. # C: O(len)
fn maybe_null_path(ptr: u64, empty_ok: bool) -> Result<alloc::string::String, i64> {
    if ptr == 0 {
        if empty_ok { return Ok(alloc::string::String::new()); }
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let s = read_path_allow_empty(ptr)?;
    if s.is_empty() && !empty_ok { return Err(-(Errno::Enoent.as_i32() as i64)); }
    Ok(s)
}

fn sys_move_mount_impl(args: &SyscallArgs) -> i64 {
    if let Some(rv) = may_mount_or_eperm() { return rv; }  // Linux may_mount (D49)
    // Flag word FIRST (Linux `SYSCALL_DEFINE5(move_mount)`: may_mount, then the
    // MOVE_MOUNT__MASK and BENEATH-xor-SET_GROUP rejects, then either pathname).
    let f = match crate::move_mount_policy::parse(args.a4) { Ok(f) => f, Err(rv) => return rv };
    let from_fd = args.a0 as i32;
    // Linux `getname_maybe_null`: with the side's `_EMPTY_PATH` bit, a NULL
    // pointer OR an empty string yields a NULL `struct filename`, which is how
    // the call is told to operate on the descriptor itself. Without the bit
    // neither shortcut applies — NULL is EFAULT and `""` is ENOENT. This is why
    // reading both pathnames unconditionally was wrong: a NULL `to_pathname`
    // with MOVE_MOUNT_T_EMPTY_PATH is legal and was reported EFAULT.
    let from_path = match maybe_null_path(args.a1, f.from.empty) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let to_path = match maybe_null_path(args.a3, f.to.empty) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let (target_mt, target) = if to_path.is_empty() {
        // MOVE_MOUNT_T_EMPTY_PATH: the destination IS `to_dfd` itself.
        let p = match crate::pathresolve::resolve_at_or_dirfd(
            args.a2 as i32, args.a3, syscall::at::AT_EMPTY_PATH) {
            Ok(p) => p, Err(rv) => return rv,
        };
        let display = vfs::mount::render_path_for_mount(p.mnt_id, &p.dentry);
        (vfs::mount_target_from_resolved_path(p), display)
    } else {
        match resolve_move_target_at(args.a2 as i32, &to_path, f.to) {
            Ok(t) => t, Err(rv) => return rv,
        }
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
    // Mode (a): from_fd refers to a detached mount object.
    if from_path.is_empty() {
        // An `fsmount(2)` fd is a PATH fd over a real anonymous mount, so the
        // move is Linux's `do_move_mount` with an anonymous source: the SAME
        // mount object leaves its anonymous namespace and joins the caller's
        // tree, keeping its id. Checked before the private-inode shapes below,
        // which are the open_tree clone cases.
        if let Some(m) = anon_mount_of_fd(from_fd) {
            return match vfs::mount::graft_anon_mount_at(&m, target_d.clone(), target_mnt) {
                Ok(()) => { let _ = vfs::mount::propagate_mount(&target_d); 0 }
                Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                Err(e) => crate::namei_common::errno_from_vfs(e),
            };
        }
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
                // A commit that spliced NOTHING is a failed graft, not a
                // success: reporting 0 here left the caller believing its
                // detached tree was attached while the fd had already given it
                // up (the `take()` above), leaking the clone.
                let n = vfs::mount::commit_tree_hashonly_at(tree, &target_d, target_mnt);
                if n == 0 { return -(Errno::Einval.as_i32() as i64); }
                return 0;
            }
            // open_tree clone (legacy non-recursive): bind the captured (fs, root).
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                return match vfs::mount::register_bind_at(
                    Some(target_d.clone()), fs.clone(), root.clone(), Some(target_mnt)) {
                    Ok(_) => 0,
                    Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                    Err(e) => crate::namei_common::errno_from_vfs(e),
                };
            }
            // Graft the already-realized SB (Linux do_move_mount over a
            // fsmount object), then deliver mount propagation to the destination
            // peer group. [D51] The `fsmount(2)` property set stored on the
            // object is mapped into the MNT_* option space and
            // stamped on the new mount BEFORE it goes live, so a following
            // `propagate_mount` peer-copy inherits it (clone_mnt copies src.flags).
            if let Some((sb, _root)) = mo.realized.as_ref() {
                let state = mo.mount_state.lock().clone();
                let mnt_flags = vfs::mount::mount_attr_to_mnt(state.attrs);
                // Parent = the mount the target-dir walk crossed into, not a
                // re-derivation from the (bind-shared) mountpoint dentry. systemd
                // creates the sandbox apivfs at /run/systemd/namespace-X after
                // rbinding / onto /run/systemd/mount-rootfs, so parent_by_dentry
                // is ambiguous; the walked mnt_id places it under the real /run.
                // The MNT_LOCK_*/MNT_LOCKED word `fsmount(2)` decided
                // (`mount_too_revealing`'s preserved attributes +
                // `create_new_namespace`'s `lock_mnt_tree`) is installed with the
                // option mask, before the mount goes live.
                let attached = vfs::mount::attach_sb_detached_at(
                    Some(target_d.clone()), sb.clone(), mnt_flags, state.lock_flags,
                    state.idmap, state.propagation, Some(target_mnt));
                return match attached {
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
    let from_vp = match crate::pathresolve::resolve_at_path(from_fd, &from_path,
        side_lookup(f.from, false)) {
        Ok(p) => p, Err(rv) => return rv,
    };
    // MOVE_MOUNT_SET_GROUP relocates nothing — it makes the DESTINATION mount
    // join the source's sharing group (Linux `do_set_group`). Both sides must
    // be mount roots, which is what `path_mounted` asks of each resolved path.
    if f.set_group {
        let (Some(from_m), Some(to_m)) = (vfs::mount::mount_by_id(from_vp.mnt_id),
                                          vfs::mount::mount_by_id(target_mt.parent.mnt_id)) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        let from_at_root = vfs::mount::root_dentry_for_mount_id(from_vp.mnt_id)
            .map(|r| alloc::sync::Arc::ptr_eq(&r, &from_vp.dentry)).unwrap_or(false);
        let to_at_root = vfs::mount::root_dentry_for_mount_id(target_mt.parent.mnt_id)
            .map(|r| alloc::sync::Arc::ptr_eq(&r, &target_d)).unwrap_or(false);
        return match vfs::mount::set_group(&from_m, from_at_root, &to_m, to_at_root) {
            Ok(()) => 0,
            Err(e) => crate::namei_common::errno_from_vfs(e),
        };
    }
    // MOVE_MOUNT_BENEATH slides the source UNDER the mount already at the
    // target, so the target path must BE that mount's root; anything else has
    // no top mount to go beneath.
    if f.beneath {
        let top_id = target_mt.parent.mnt_id;
        let at_root = vfs::mount::root_dentry_for_mount_id(top_id)
            .map(|r| alloc::sync::Arc::ptr_eq(&r, &target_d)).unwrap_or(false);
        if !at_root { return -(Errno::Einval.as_i32() as i64); }
        return match vfs::mount::move_mount_beneath(from_vp.mnt_id, top_id) {
            Ok(()) => 0,
            Err(e) => crate::namei_common::errno_from_vfs(e),
        };
    }
    // Destination mount id from the walk: disambiguates a `to` sitting in a bind
    // mount (shared dentries defeat `parent_by_dentry`). Falls back to `target_d`.
    match vfs::mount::move_mount_by_id_to_rendered(from_vp.mnt_id, Some(target_mnt), &target_d, target) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}

/// The anonymous mount an `fsmount(2)` fd refers to, if that is what `fd` is.
///
/// `None` for every other fd — an ordinary path fd, an `open_tree` clone
/// object, or a closed slot — so the caller falls through to the shapes it
/// handled before. The mount must still be an ANONYMOUS ROOT: an fd whose
/// mount was already moved is no longer a source, which is what makes a second
/// `move_mount(2)` on the same fd EINVAL rather than a second attach.
/// # C: O(log N)
fn anon_mount_of_fd(fd: i32) -> Option<alloc::sync::Arc<vfs::mount::Mount>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let file = fdt.get(fd).ok()?;
    let id = file.need_unmount();
    if id == 0 { return None; }
    let m = vfs::mount::mount_by_id(id)?;
    if vfs::mount::anon_ns_root(&m) { Some(m) } else { None }
}
