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

/// # C: O(1) un-chrooted; O(jail components) chrooted
pub(super) fn resolution_root() -> Option<(Arc<vfs::Dentry>, bool)> {
    let global = root_dentry()?;
    let Some(cur) = sched::live::current() else { return Some((global, false)); };
    // SAFETY: task.root_vfs single-mutator per 13§5; the running task on this CPU is the sole writer.
    if let Some(p) = unsafe { (*cur.root_vfs.get()).clone() } {
        return Some((p.dentry, true));
    }
    // SAFETY: task.root single-mutator per 13§5; the running task on this CPU is the sole writer.
    let rp = unsafe { (*cur.root.get()).clone() };
    if rp == "/" { return Some((global, false)); }
    let f = vfs::LookupFlags::default();
    let (_i, d) = vfs::path_lookup(global.clone(), global, &rp, f).ok()?;
    Some((d, true))
}
