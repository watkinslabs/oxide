// 428 open_tree — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

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
    const AT_RECURSIVE:      u64 = 0x8000;          // clone the whole subtree
    const AT_EMPTY_PATH:     u64 = 0x1000;
    let vp = match crate::pathresolve::resolve_at_lookup(args.a0 as i32, args.a1, vfs::LookupFlags {
        empty: (args.a2 & AT_EMPTY_PATH) != 0,
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
        klog::write_raw(if args.a2 & AT_RECURSIVE != 0 { b"true" } else { b"false" });
        klog::write_raw(b" source="); klog::write_raw(display.as_bytes());
        klog::write_raw(b" target=<none>\n");
    }
    let cloexec = (args.a2 & OPEN_TREE_CLOEXEC) != 0;
    if (args.a2 & OPEN_TREE_CLONE) != 0 {
        // OPEN_TREE_CLONE creates a detached mount → requires CAP_SYS_ADMIN
        // (Linux open_detached_copy/may_mount); the non-clone O_PATH-like form
        // below is unprivileged (D49).
        if let Some(rv) = may_mount_or_eperm() { return rv; }
        // D24 Stage 1a: RECURSIVELY clone the mount SUBTREE rooted at `abs`
        // (AT_RECURSIVE ⇒ whole bindable subtree; else root-only) into a
        // DETACHED node list stored in the mount-object fd. `move_mount` later
        // commits it hash-only; fd-close releases it. This replaces the prior
        // single-(fs,root) capture that never replicated submounts.
        let recursive = (args.a2 & AT_RECURSIVE) != 0;
        let mnt = match vfs::mount::mount_by_id(vp.mnt_id) {
            Some(m) => m,
            None => {
                crate::mount_common::mnt_log("open_tree_clone_NONE", &display, -(Errno::Enoent.as_i32() as i64));
                return -(Errno::Enoent.as_i32() as i64);
            }
        };
        let tree = vfs::mount::clone_mount_tree(&mnt, recursive);
        if tree.is_empty() { return -(Errno::Einval.as_i32() as i64); }
        // Linux `fs/namespace.c` `create_new_namespace` (reached from
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
    // Non-clone: an fd referring to the path's inode (O_PATH-ish).
    install_fd(vp.inode, "open_tree", cloexec)
}
