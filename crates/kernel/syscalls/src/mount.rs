// mount — VFS path-walk hook + mount-ns provider installer (docs/53 §0).
// The mount-family syscall handlers (sys_mount/sys_umount2/sys_pivot_root)
// moved to per-file modules: s165_mount, s166_umount2, s155_pivot_root.
// Shared helper read_user_cstr_owned lives in mount_common.

#![cfg(target_os = "oxide-kernel")]

/// The calling task's mount-namespace id (`docs/16§6`), or 0 at boot /
/// kthread context. Installed into `vfs::mount` so `register` can stamp
/// each mount's owning ns without threading it through every call site.
/// # C: O(1)
fn current_mount_ns() -> u64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|c| c.mount_ns.load(Ordering::Acquire)).unwrap_or(0)
}

/// Install the VFS path-walk hooks (mount-crossing) AND the mount-ns
/// provider at boot. Resolution is now always per-component
/// (`d_lookup → i_op->lookup → d_add`); there is no whole-path delegate to
/// install (WP2 deleted `FileSystem::lookup`).
/// # C: O(1)
pub fn install_vfs_hooks() {
    vfs::mount::set_current_ns_provider(current_mount_ns);
    // The mount engine NEVER resolves a mount-point STRING to a dentry
    // (`docs/16§3`): every caller hands `register*`/`move_mount`/… the
    // `Arc<Dentry>` its namei walk produced. The only provider needed is the
    // global root dentry — the start of the owning-mount identification walk
    // (`resolve_mount` → namei `walk_to_mount`) AND of the engine-internal
    // `descend` that materialises SYNTHESIZED mount positions.
    vfs::set_root_dentry_provider(crate::pathresolve::root_dentry);
}
