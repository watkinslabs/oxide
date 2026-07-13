#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use sync::{MountTable as RootClass, Spinlock};

static ROOT_DENTRY: Spinlock<Option<Arc<vfs::Dentry>>, RootClass> = Spinlock::new(None);

pub fn root_dentry() -> Option<Arc<vfs::Dentry>> {
    {
        let g = ROOT_DENTRY.lock();
        if let Some(d) = g.as_ref() { return Some(d.clone()); }
    }
    let root_inode = ext4::rootfs::lookup_inode_any(b"/")?;
    let d = vfs::Dentry::new_root(root_inode);
    let mut g = ROOT_DENTRY.lock();
    Some(g.get_or_insert(d).clone())
}

/// Resolution root with its exact mount id. `root_vfs` is a full `struct path`
/// equivalent; dropping its `mnt_id` and re-deriving from the dentry is wrong
/// after bind/pivot clones that share one superblock root.
pub(super) fn resolution_root_vfs() -> Option<(vfs::VfsPath, bool)> {
    let global = root_dentry()?;
    let ns = vfs::mount::current_ns();
    let namespace_root = || -> Option<vfs::VfsPath> {
        let mnt_id = vfs::mount::root_mount_id(ns)?;
        let dentry = vfs::mount::root_dentry_for_mount_id(mnt_id)?;
        let inode = dentry.inode()?;
        Some(vfs::VfsPath { mnt_id, dentry, inode, last_component: None })
    };
    let Some(cur) = sched::live::current() else {
        if let Some(p) = namespace_root() { return Some((p, false)); }
        let inode = global.inode()?;
        return Some((vfs::VfsPath { mnt_id: vfs::mount::MNT_ID_NONE, dentry: global, inode, last_component: None }, false));
    };
    // SAFETY: task.root_vfs single-mutator per 13§5; the running task on this CPU is the sole writer.
    if let Some(p) = unsafe { (*cur.root_vfs.get()).clone() } {
        if p.mnt_id == vfs::mount::MNT_ID_NONE {
            if let Some(p) = namespace_root() { return Some((p, false)); }
        } else {
            return Some((p, true));
        }
    }
    // SAFETY: task.root single-mutator per 13§5; the running task on this CPU is the sole writer.
    let rp = unsafe { (*cur.root.get()).clone() };
    if rp == "/" {
        if let Some(p) = namespace_root() { return Some((p, false)); }
        let inode = global.inode()?;
        return Some((vfs::VfsPath { mnt_id: vfs::mount::MNT_ID_NONE, dentry: global, inode, last_component: None }, false));
    }
    let f = vfs::LookupFlags::default();
    let p = vfs::path_lookup_path(global.clone(), global, &rp, f).ok()?;
    Some((p, true))
}
