// 428 open_tree — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

/// `sys_open_tree(dirfd, path, flags)` — slot 428. `OPEN_TREE_CLONE`
/// detaches a CLONE of the mount at `path` into an fd (the source for a
/// later `move_mount`); `OPEN_TREE_NAMESPACE` puts that copy in a new mount
/// namespace and hands back the NAMESPACE fd instead; without either, returns
/// an O_PATH-like fd referring to the path. `OPEN_TREE_CLOEXEC = O_CLOEXEC`.
/// systemd uses the clone form for `RootDirectory=`/sandbox setup.
/// # C: O(N_mounts)
pub fn sys_open_tree(args: &SyscallArgs) -> i64 {
    match crate::open_tree_policy::parse(args.a2) {
        Ok(f) => open_tree_decided(args, f),
        Err(rv) => rv,
    }
}

/// The flag word is already decoded + validated (`open_tree_policy`), so the
/// only work left is the walk and the fd. Split out so `open_tree_attr(2)`
/// reuses the identical decision without re-parsing.
/// # C: O(N_mounts)
pub fn open_tree_decided(args: &SyscallArgs, f: crate::open_tree_policy::OpenTree) -> i64 {
    // The privilege rung runs BEFORE the walk, so an unprivileged caller naming
    // a nonexistent path is told EPERM, not ENOENT. WHICH privilege depends on
    // the form — the namespace form asks only about the caller's own user
    // namespace — and that selection lives in the ungated policy module with
    // `fsmount(2)`'s, because it is the same pair of rungs.
    if let Err(rv) = crate::open_tree_policy::admit_privilege(f, sample_caps()) { return rv; }
    let vp = match crate::pathresolve::resolve_at_lookup(args.a0 as i32, args.a1, vfs::LookupFlags {
        empty: f.empty,
        follow: f.follow,
        no_follow_final: !f.follow,
        no_automount: !f.automount,
        ..Default::default()
    }) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let display = vfs::mount::render_path_for_mount(vp.mnt_id, &vp.dentry);
    // TEMP (D24, debug-mnt): mount-creating syscall ENTRY trace (Stage-1a
    // replication source) — pair with vfs [MNTCREATE] clone/commit_hashonly.
    #[cfg(feature = "debug-mount")]
    {
        klog::write_raw(b"[MNTCREATE] syscall=open_tree flags=0x");
        klog::write_hex_u64(args.a2);
        klog::write_raw(b" recursive=");
        klog::write_raw(if f.recursive { b"true" } else { b"false" });
        klog::write_raw(b" source="); klog::write_raw(display.as_bytes());
        klog::write_raw(b" target=<none>\n");
    }
    let cloexec = f.cloexec;
    if f.namespace {
        // The sibling of `fsmount(FSMOUNT_NAMESPACE)`, and it goes through the
        // SAME constructor: the namespace both syscalls hand back has one shape
        // — a copy of the caller's namespace root with the requested tree
        // mounted on top of it — and writing that twice is writing two shapes.
        let mnt = match vfs::mount::mount_by_id(vp.mnt_id) {
            Some(m) => m,
            None => return -(Errno::Enoent.as_i32() as i64),
        };
        let created = vfs::mount::create_new_namespace(vfs::mount::NsMountSource::Tree {
            src: mnt, base: vp.dentry.clone(), recursive: f.recursive,
        });
        let (_top, ns) = match created {
            Ok(pair) => pair,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        // The descriptor IS the namespace: it is what `setns(2)` takes, and
        // holding it is what keeps the namespace — and the mounts inside it —
        // alive, since nothing else refers to a freshly named one.
        return install_fd(nscg::proc_ns::mnt_ns_inode(ns), "[mntns]", cloexec);
    }
    if f.clone_tree {
        // D24 Stage 1a: RECURSIVELY clone the mount SUBTREE rooted at `abs`
        // (AT_RECURSIVE ⇒ whole bindable subtree; else root-only) into a
        // DETACHED node list stored in the mount-object fd. `move_mount` later
        // commits it hash-only; fd-close releases it. This replaces the prior
        // single-(fs,root) capture that never replicated submounts.
        let recursive = f.recursive;
        let mnt = match vfs::mount::mount_by_id(vp.mnt_id) {
            Some(m) => m,
            None => {
                crate::mount_common::mnt_log("open_tree_clone_NONE", &display, -(Errno::Enoent.as_i32() as i64));
                return -(Errno::Enoent.as_i32() as i64);
            }
        };
        // Linux `__do_loopback`: unbindable / cross-namespace / locked-children
        // rungs, all EINVAL, before anything is copied.
        if let Err(e) = vfs::mount::may_clone_mount_tree(&mnt, &vp.dentry, recursive) {
            return crate::namei_common::errno_from_vfs(e);
        }
        let tree = vfs::mount::clone_mount_tree(&mnt, recursive);
        if tree.is_empty() { return -(Errno::Einval.as_i32() as i64); }
        // Linux's `create_new_namespace` (reached from
        // `open_tree(OPEN_TREE_CLONE)` via `open_new_namespace`): `if (user_ns !=
        // ns->user_ns) lock_mnt_tree(new_ns_root);`. A caller whose CURRENT user
        // namespace is not the one owning its mount namespace is unprivileged
        // with respect to the mounter of the tree it just copied — freeze the
        // copy's protections and mark it MNT_LOCKED so a later `move_mount` +
        // remount cannot relax them, or unmount a node to reveal what it covers.
        if crate::mount_perm::current_user_ns_differs_from_mount_ns_owner() {
            vfs::mount::lock_detached_tree(&tree);
        }
        let mo = MountObjectInode::new_clone_tree(tree);
        return install_fd(mo, "open_tree", cloexec);
    }
    // Non-clone: Linux `dentry_open(&path, O_PATH, current_cred())`. Preserve
    // the complete f_path so AT_EMPTY_PATH consumers operate on this mount.
    install_path_fd(vp, cloexec)
}
