//! Running-task VFS lookup context shared by syscall and sysfs owners.

/// One snapshot of the caller's Linux `fs_struct` root and cwd.  Path-owning
/// work must consume this object instead of recreating a global-root lookup.
pub struct VfsLookupContext {
    pub start: vfs::VfsPath,
    pub root: vfs::VfsPath,
    pub beneath: bool,
}

/// Snapshot the current task's explicit VFS root and cwd.  `None` preserves
/// the early-boot fallback owner for callers running before task fs state has
/// been installed. # C: O(1)
pub fn current_vfs_lookup_context() -> Option<VfsLookupContext> {
    let task = super::current()?;
    // SAFETY: root_vfs is single-mutator per 13§5; the running task is its sole writer.
    let root = unsafe { (*task.root_vfs.get()).clone() }?;
    if root.mnt_id == vfs::mount::MNT_ID_NONE { return None; }
    // SAFETY: cwd_vfs is single-mutator per 13§5; the running task is its sole writer.
    let start = unsafe { (*task.cwd_vfs.get()).clone() }
        .filter(|path| path.mnt_id != vfs::mount::MNT_ID_NONE)
        .unwrap_or_else(|| root.clone());
    Some(VfsLookupContext { start, root, beneath: true })
}
