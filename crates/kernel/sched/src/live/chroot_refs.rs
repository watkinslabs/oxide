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
use vfs::{Dentry, VfsPath};

/// True iff `p` is a path rooted EXACTLY at the old root mount's root dentry
/// (same `mnt_id` AND same root dentry — not a subdirectory within it).
/// # C: O(1)
fn at_old_root(p: &Option<VfsPath>, old_mnt: u64, old_dentry: Option<&Arc<Dentry>>) -> bool {
    match p {
        Some(vp) if vp.mnt_id == old_mnt => match old_dentry {
            Some(od) => Arc::ptr_eq(&vp.dentry, od),
            // Old root mount has no resolvable root dentry: fall back to the
            // mnt_id match alone (the mount is being re-rooted regardless).
            None => true,
        },
        _ => false,
    }
}

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
        // SAFETY: task.root_vfs / cwd_vfs are single-mutator per `13§5`; v1 is
        // uniprocessor (UP) and this hook runs synchronously inside the
        // pivot_root syscall, so no other task is executing concurrently to
        // race these slots. Each repoint clones a fresh VfsPath of the new root.
        unsafe {
            if at_old_root(&*t.root_vfs.get(), old_root, od.as_ref()) {
                *t.root_vfs.get() = Some(VfsPath {
                    mnt_id: new_root, dentry: nd.clone(), inode: ni.clone(), last_component: None,
                });
            }
            if at_old_root(&*t.cwd_vfs.get(), old_root, od.as_ref()) {
                *t.cwd_vfs.get() = Some(VfsPath {
                    mnt_id: new_root, dentry: nd.clone(), inode: ni.clone(), last_component: None,
                });
            }
        }
    }
}
