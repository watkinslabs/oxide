extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{KResult, VfsError};

/// Negative-dentry caching safety gate for filesystem-backed directories.
/// # C: O(1)
pub(crate) fn neg_cache_ok(dir: &InodeRef) -> bool {
    match dir.i_sb() {
        Some(sb) => matches!(sb.s_type.name(), "ext4" | "tmpfs" | "ramfs"),
        None => false,
    }
}

/// Follow stacked mountpoints DOWN from `d`: while `d` is a mountpoint, switch
/// to the mounted fs's `s_root` dentry (Linux `__follow_mount`). Returns the
/// final dentry, its inode, and the deepest crossed mount id. # C: O(stack)
pub(crate) fn follow_mount_down(mut d: Arc<Dentry>, mut mnt_id: u64) -> KResult<(Arc<Dentry>, InodeRef, u64)> {
    // [D24] Cross stacked mounts via the strict `(parent_mnt_id, dentry)` mount
    // hash (Linux `__lookup_mnt`): while a mount is attached on `d` whose PARENT
    // is the current mount `mnt_id`, switch to that child mount's root dentry and
    // adopt its id, looping for stacked overmounts. The parent-keyed hash is
    // ns-correct (every namespace mints ns-private mnt_ids), so the legacy
    // parent-agnostic `dentry.mounted_mounts` map is no longer consulted (deleted).
    while let Some(m) = crate::mount::__lookup_mnt(mnt_id, &d) {
        match m.mnt_root() {
            Some(sr) => { d = sr; mnt_id = m.mnt_id; }
            None => break,
        }
    }
    let inode = d.inode().ok_or(VfsError::Enoent)?;
    Ok((d, inode, mnt_id))
}

/// `..` step with `follow_dotdot` mount-crossing (Linux). Clamps at the
/// resolution root (`/.. == /`, chroot/BENEATH/IN_ROOT confinement). At a
/// mounted fs root that is not the resolution root, cross back to the
/// mountpoint in the parent mount (looping for stacked roots), THEN take the
/// normal parent step. Returns `true` when the step was an ESCAPE attempt —
/// `..` at the resolution root, which is clamped (held at root) here but which
/// `RESOLVE_BENEATH` (`beneath_exdev`) turns into `EXDEV`. # C: O(stack)
pub(crate) fn dotdot_step(
    cur_dentry: &mut Arc<Dentry>,
    cur_mnt: &mut u64,
    cur_inode: &mut InodeRef,
    root_dentry: &Arc<Dentry>,
    root_mnt: u64,
) -> bool {
    loop {
        if Arc::ptr_eq(cur_dentry, root_dentry) { return true; }
        if cur_dentry.is_root() && *cur_mnt != root_mnt {
            if let Some((mp, parent_mnt)) = crate::mount::mountpoint_of(*cur_mnt) {
                *cur_dentry = mp;
                *cur_mnt = parent_mnt;
                if let Some(i) = cur_dentry.inode() { *cur_inode = i; }
                continue;
            }
        }
        break;
    }
    if let Some(par) = cur_dentry.parent() {
        let par = par.clone();
        if let Some(pi) = par.inode() { *cur_inode = pi; *cur_dentry = par; }
    }
    false
}

/// Split `path` into the walk queue's owned component strings.
/// # C: O(len)
pub(crate) fn components(path: &str) -> Vec<String> {
    crate::path::components(path).into_iter().filter_map(|c| match c {
        crate::path::Component::Root      => None,                  // leading '/' → walk's to_root()
        crate::path::Component::ParentDir => Some(String::from("..")),
        crate::path::Component::Normal(s) => Some(String::from(s)),
    }).collect()
}
