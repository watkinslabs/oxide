#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use sync::{MountTable as RootClass, Spinlock};

static ROOT_DENTRY: Spinlock<Option<Arc<vfs::Dentry>>, RootClass> = Spinlock::new(None);

/// The global resolution root: the root mount's own root dentry.
///
/// Linux takes it from the mounted root — `d_make_root` builds the superblock's
/// `s_root` and `init_mount_tree` makes that the initial `fs_struct` root. It
/// was taken from ext4's private rootfs API here instead, which meant the whole
/// namespace resolved only while ext4 was the root filesystem: mount a squashfs
/// root and every path, `/dev` included, answered ENOENT with the mount grafted
/// and nothing to say why.
///
/// Cached after the first answer: the root mount does not change, and the
/// dentry's identity is what the dcache keys on.
/// # C: O(1) after the first call
pub fn root_dentry() -> Option<Arc<vfs::Dentry>> {
    {
        let g = ROOT_DENTRY.lock();
        if let Some(d) = g.as_ref() { return Some(d.clone()); }
    }
    let d = vfs::mount::root_path_for_ns(vfs::mount::current_ns()).map(|p| p.dentry)?;
    let mut g = ROOT_DENTRY.lock();
    Some(g.get_or_insert(d).clone())
}

/// Resolution root with its exact mount id. `root_vfs` is a full `struct path`
/// equivalent; dropping its `mnt_id` and re-deriving from the dentry is wrong
/// after bind/pivot clones that share one superblock root.
pub(super) fn resolution_root_vfs() -> Option<(vfs::VfsPath, bool)> {
    let global = root_dentry()?;
    let ns = vfs::mount::current_ns();
    let namespace_root = || -> Option<vfs::VfsPath> { vfs::mount::root_path_for_ns(ns) };
    let Some(cur) = sched::live::current() else {
        if let Some(p) = namespace_root() { return Some((p, false)); }
        let inode = global.inode()?;
        return Some((vfs::VfsPath { mnt_id: vfs::mount::MNT_ID_NONE, dentry: global, inode, last_component: None }, false));
    };
    let snapshot = cur.fs_context_snapshot();
    if let Some(p) = snapshot.root_vfs() {
        if p.mnt_id == vfs::mount::MNT_ID_NONE {
            if let Some(p) = namespace_root() { return Some((p, false)); }
        } else {
            return Some((p, true));
        }
    }
    let rp = snapshot.root();
    if rp == "/" {
        if let Some(p) = namespace_root() { return Some((p, false)); }
        let inode = global.inode()?;
        return Some((vfs::VfsPath { mnt_id: vfs::mount::MNT_ID_NONE, dentry: global, inode, last_component: None }, false));
    }
    let f = vfs::LookupFlags::default();
    let p = vfs::path_lookup_path(global.clone(), global, &rp, f).ok()?;
    Some((p, true))
}
