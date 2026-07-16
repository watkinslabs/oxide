// mount — VFS path-walk hook + mount-ns provider installer (docs/53 §0).
// The mount-family syscall handlers (sys_mount/sys_umount2/sys_pivot_root)
// moved to per-file modules: s165_mount, s166_umount2, s155_pivot_root.
// Shared helper read_user_cstr_owned lives in mount_common.

#![cfg(target_os = "oxide-kernel")]

/// Retain the calling task's mount namespace (`docs/16§6`), or init at boot /
/// kthread context. Installed into `vfs::mount` so `register` can stamp
/// each mount's owning ns without threading it through every call site.
/// # C: O(1)
fn current_mount_ns() -> vfs::mntns::MntNamespaceRef {
    sched::live::current().and_then(sched::Task::mount_namespace_snapshot)
        .unwrap_or_else(vfs::mntns::initial)
}

/// Install the VFS path-walk hooks (mount-crossing) AND the mount-ns
/// provider at boot. Resolution is now always per-component
/// (`d_lookup → i_op->lookup → d_add`); there is no whole-path delegate to
/// install (WP2 deleted `FileSystem::lookup`).
/// # C: O(1)
pub fn install_vfs_hooks() {
    vfs::mount::set_current_ns_provider(current_mount_ns);
    vfs::superblock::set_freeze_wait_hooks(
        sched::live::sb_freeze::park,
        sched::live::sb_freeze::schedule_after_park,
        sched::live::sb_freeze::wake,
    );
    vfs::set_quota_wait_hooks(
        sched::live::quota_wait::park,
        sched::live::quota_wait::schedule_after_park,
        sched::live::quota_wait::wake,
    );
    vfs::inode::set_inode_rwsem_wait_hooks(
        sched::live::inode_wait::park,
        sched::live::inode_wait::schedule_after_park,
        sched::live::inode_wait::wake,
    );
    // The mount engine NEVER resolves a mount-point STRING to a dentry
    // (`docs/16§3`): every caller hands `register*`/`move_mount`/… the
    // `Arc<Dentry>` its namei walk produced. The only provider needed is the
    // global root dentry — the start of the owning-mount identification walk
    // (`resolve_mount` → namei `walk_to_mount`) AND of the engine-internal
    // `descend` that materialises SYNTHESIZED mount positions.
    vfs::set_root_dentry_provider(crate::pathresolve::root_dentry);
    // pivot_root chroot-refs (Linux `chroot_fs_refs`): vfs commits the re-root
    // then calls this hook to re-point every task whose root/cwd was on the old
    // root mount to the new root. The walk lives in sched (it owns the task
    // table). Last-writer-wins with the vfs test's own hook; in production this
    // is the only installer.
    vfs::mount::set_chroot_refs_hook(sched::live::chroot_fs_refs);
    // Wall clock for `file_update_time` / `current_time`: vfs owns no time
    // source, so it reads the canonical CLOCK_REALTIME provider. Without it a
    // write-stamped mtime would
    // be frozen at the epoch.
    vfs::inode_times::set_realtime_provider(timekeeper::realtime_ns);
}
