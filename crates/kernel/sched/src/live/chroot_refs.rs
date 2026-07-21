// pivot_root chroot-refs hook (Linux `fs/namespace.c:chroot_fs_refs`).
//
// vfs commits a pivot_root then calls the installed hook with the OLD and NEW
// root mount ids; vfs cannot walk the task table (sched owns it), so the real
// implementation lives here. Every task whose fs root (or cwd) pointed EXACTLY
// at the old root mount's root dentry is re-pointed at the new root — the
// behaviour of Linux `chroot_fs_refs` over the tasklist. Tasks rooted/cwd'd
// anywhere else (a different mount, or a subtree dentry within the old root)
// are left untouched.

use alloc::sync::Arc;
use vfs::VfsPath;

/// Linux `chroot_fs_refs(old_root, new_root)` over the live tasklist. Invoked
/// by `vfs::mount::pivot_root` via the installed `CHROOT_HOOK`. Re-points each
/// task whose root/cwd VfsPath was on the old root mount to the new root.
///
/// Registered at boot through `vfs::mount::set_chroot_refs_hook` (see
/// `syscalls::mount::install_vfs_hooks`).
/// # C: O(N_tasks)
pub fn chroot_fs_refs(old_root: u64, new_root: u64) {
    // New root path == {new_mnt, new_mnt->mnt_root} — the new root mount's root
    // dentry, which pivot_root makes the namespace "/". Bail if the new root is
    // not resolvable (nothing safe to repoint to).
    let nd = match vfs::mount::root_dentry_for_mount_id(new_root) { Some(d) => d, None => return };
    let ni = match vfs::mount::root_for_mount_id(new_root) { Some(i) => i, None => return };
    let od = vfs::mount::root_dentry_for_mount_id(old_root);

    let tasks = match crate::registry::try_snapshot() { Some(t) => t, None => return };
    for t in tasks.iter() {
        let replacement = VfsPath { mnt_id: new_root, dentry: nd.clone(), inode: ni.clone(), last_component: None };
        t.repoint_fs_old_root(old_root, od.as_ref(), &replacement);
    }
}
