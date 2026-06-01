// Shared path-resolution helpers used by every syscall that takes a
// user-mode path argument. Centralizes the cwd-join + lexical-normalize
// dance so we don't fork the rule (skip "." vs preserve ".", etc.) per
// callsite.
//
// All resolution is lexical only (no FS lookup, no symlink expansion).
// Caller hands the result to vfs::mount::lookup / ext4::rootfs::* /
// other backends.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use sync::{MountTable as RootClass, Spinlock};

/// Cached root dentry — the start of every absolute `path_lookup`. Built
/// lazily from the ext4 root inode (ext4 is mounted at `/`). One global
/// node shared by all tasks (dentries are process-independent; only
/// cwd/root pointers are per-task). chroot/dirfd bases ride later stages.
static ROOT_DENTRY: Spinlock<Option<Arc<vfs::Dentry>>, RootClass> = Spinlock::new(None);

fn root_dentry() -> Option<Arc<vfs::Dentry>> {
    {
        let g = ROOT_DENTRY.lock();
        if let Some(d) = g.as_ref() { return Some(d.clone()); }
    }
    let root_inode = ext4::rootfs::lookup_inode_any(b"/")?;
    let d = vfs::Dentry::new_root(root_inode);
    let mut g = ROOT_DENTRY.lock();
    Some(g.get_or_insert(d).clone())
}

/// Resolve absolute `abs` to its inode via the dentry path-walk
/// (`vfs::path_lookup`) — THE resolver (`docs/16§3`): per-component,
/// crossing mounts (`mount_root_at`) and delegating whole-path
/// filesystems (`mount_whole_path`) to their owning mount, following
/// symlinks (intermediate always; final unless `no_follow_final`) with
/// ELOOP at depth>40. Returns `None` if unresolved or ext4 isn't mounted
/// yet (very early boot). `no_follow_final` = O_NOFOLLOW /
/// AT_SYMLINK_NOFOLLOW (lstat).
/// # C: O(components × dir-lookup)
pub fn resolve(abs: &str, no_follow_final: bool) -> Option<vfs::InodeRef> {
    let root = root_dentry()?;
    let flags = vfs::LookupFlags { no_follow_final, ..Default::default() };
    vfs::path_lookup(root.clone(), root, abs, flags).ok().map(|(i, _)| i)
}

/// Resolve `raw` against the running task's cwd. Absolute paths
/// short-circuit through the lexical normalizer (collapses `.` /
/// `..`); relative paths are joined to cwd then normalized.
/// Falls back to the raw string only when no current task or the
/// normalize step rejected `..`-escapes-root.
/// # C: O(N_path components)
pub fn resolve_cwd(raw: &str) -> String {
    if raw.starts_with('/') {
        return vfs::path::lexical_normalize(raw).unwrap_or_else(|| raw.into());
    }
    let Some(cur) = sched::live::current() else { return raw.into(); };
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, raw).unwrap_or_else(|| raw.into())
}
