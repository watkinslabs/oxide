// The canonical `current_cred()` snapshot handed to the VFS permission
// engine. Every other crate that needs a caller credential calls THIS —
// there is no second place that reads `task.creds` into a `vfs::Cred`.

use core::sync::atomic::Ordering;

/// Snapshot the running task's filesystem credentials for VFS permission
/// checks. Path-owning kernel work must not silently elevate to root.
/// # C: O(1)
pub fn current_vfs_cred() -> vfs::Cred {
    let Some(task) = crate::current() else { return vfs::Cred::root(); };
    let effective = task.creds.cap_effective.load(Ordering::Acquire);
    task.creds.to_vfs_cred(task.creds.fsuid.load(Ordering::Acquire),
        task.creds.fsgid.load(Ordering::Acquire), effective)
}

/// Snapshot the running task's complete opener credentials for a VFS file.
/// # C: O(1)
pub fn current_vfs_file_cred() -> vfs::FileCred {
    let Some(task) = crate::current() else { return vfs::FileCred::root(); };
    let effective = task.creds.cap_effective.load(Ordering::Acquire);
    let Some(user_namespace) = task.namespace_owner(namespace_identity::NamespaceKind::User) else {
        return vfs::FileCred::root();
    };
    vfs::FileCred::new(current_vfs_cred(), user_namespace, effective)
}
