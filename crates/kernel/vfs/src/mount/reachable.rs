// `is_path_reachable(mnt, dentry, root)` (`docs/16§6`) — THE one definition of
// "does this `struct path` lie at or below the caller's root?".
//
// Four callers observe it: `pivot_root(2)`'s two reachability rungs, and the
// `statmount(2)` / `listmount(2)` visibility gates (a mount outside the
// caller's root is EPERM unless the caller is CAP_SYS_ADMIN in the owning user
// namespace). Keeping it in one place is what stops those four from drifting.
//
// The walk carries a `(mnt_id, dentry)` PAIR up the mount tree, not a dentry
// alone: bind mounts SHARE dentries, so a dentry by itself cannot say which
// mount a path is in.

use super::*;

/// Linux `is_path_reachable`: climb the MOUNT chain from `(mnt, d)` towards
/// `root_mnt`, replacing the carried dentry with each mount's mountpoint, then
/// require the carried dentry to be at or below `root_d`.
///
/// The climb stops at a self-parented mount (`!mnt_has_parent`), which is this
/// tree's namespace root — reaching it without hitting `root_mnt` means the
/// path is outside the caller's root.
///
/// The namespace root mount accepts the global root dentry as an alias of its
/// own `mnt_root`: mountpoints attached directly under the namespace root are
/// materialized from the global root dentry, so a strict `s_root` identity test
/// would call every one of them unreachable.
/// # C: O(depth)
pub fn path_reachable_from_root(mut mnt: u64, d: &Arc<Dentry>, root_mnt: u64, root_d: &Arc<Dentry>) -> bool {
    let mut d = d.clone();
    while mnt != root_mnt {
        let Some(m) = mount_by_id(mnt) else { return false; };
        if m.is_root() { break; }
        let Some(mp) = m.mountpoint() else { break; };
        d = mp;
        mnt = m.parent_id.load(Ordering::Acquire);
    }
    if mnt != root_mnt { return false; }
    if d.is_subdir_of(root_d) { return true; }
    // Root-dentry alias: the namespace root mount's `mnt_root` and the global
    // root dentry name the same position.
    let Some(target) = mount_by_id(root_mnt) else { return false; };
    if !target.is_root() { return false; }
    let aliases = |a: &Arc<Dentry>| -> bool {
        global_root().map(|g| Arc::ptr_eq(&g, a)).unwrap_or(false)
            || target.mnt_root().map(|r| Arc::ptr_eq(&r, a)).unwrap_or(false)
    };
    if aliases(root_d) {
        return aliases(&d)
            || target.mnt_root().map(|r| d.is_subdir_of(&r)).unwrap_or(false)
            || global_root().map(|g| d.is_subdir_of(&g)).unwrap_or(false);
    }
    false
}

/// [`path_reachable_from_root`] against a root given as a MOUNT rather than a
/// `struct path` — the root dentry is that mount's own `mnt_root`, which is
/// what `pivot_root(2)`'s two rungs compare against. `false` for an unknown id.
/// # C: O(depth)
pub fn reachable_from_mount_root(mnt: u64, d: &Arc<Dentry>, root_mnt: u64) -> bool {
    let Some(root_d) = mount_by_id(root_mnt).and_then(|m| m.mnt_root()) else { return false; };
    path_reachable_from_root(mnt, d, root_mnt, &root_d)
}

/// [`path_reachable_from_root`] for a mount's OWN root position — the form both
/// `statmount(2)` and `listmount(2)` ask ("is mount `mnt_id` visible from this
/// root?"). `false` for an unknown id. # C: O(depth)
pub fn mount_reachable_from(mnt_id: u64, root_mnt: u64, root_d: &Arc<Dentry>) -> bool {
    let Some(m) = mount_by_id(mnt_id) else { return false; };
    let Some(r) = m.mnt_root() else { return false; };
    path_reachable_from_root(mnt_id, &r, root_mnt, root_d)
}
