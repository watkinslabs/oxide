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

/// Install the VFS path-walk hooks (mount-crossing + whole-path
/// delegation) AND the mount-ns provider at boot. Replaces the bare
/// `vfs::mount::install_resolvers()` call so lib.rs stays net-zero at the
/// 1000-line cap while gaining ns stamping.
/// # C: O(1)
pub fn install_vfs_hooks() {
    vfs::mount::install_resolvers();
    vfs::mount::set_current_ns_provider(current_mount_ns);
    // Mount crossing is dentry-identity-keyed (`docs/16§3`): give
    // `vfs::mount::register*` the resolver that maps a mount-point path to
    // its canonical dentry so it can mark that dentry a mount point.
    vfs::mount::set_dentry_resolver(crate::pathresolve::resolve_dentry);
}
