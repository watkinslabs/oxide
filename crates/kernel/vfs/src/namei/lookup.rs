extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{KResult, VfsError};

use super::{Cred, LastType, LookupFlags, MountTarget, Nameidata, VfsPath};

/// Resolve `path` from `start` with `root`, returning `(inode, dentry)`.
/// Compatibility wrapper over `path_lookup_path`; default-allow cred.
/// # C: O(components) + O(symlinks)
pub fn path_lookup(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
) -> KResult<(InodeRef, Arc<Dentry>)> {
    let p = path_lookup_path(start, root, path, flags)?;
    Ok((p.inode, p.dentry))
}

/// Resolve `path` to a full `VfsPath`, preserving the mount identity that owns
/// the final dentry. Default-allow cred (`Cred::root()`); use
/// `path_lookup_cred` to enforce per-directory search permission.
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_path(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
) -> KResult<VfsPath> {
    path_lookup_cred(start, root, path, flags, Cred::root())
}

/// Resolve `path` to a full `VfsPath`, enforcing `may_lookup` (MAY_EXEC) on
/// each traversed directory against `cred` (Linux `link_path_walk`).
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_cred(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
    cred: Cred,
) -> KResult<VfsPath> {
    let mut nd = Nameidata::new(start, root, flags, cred)?;
    nd.walk(path)
}

/// `*at` resolution that seeds the walk from a `start` carrying its REAL
/// `start_mnt_id` (the dirfd's `f.mnt_id()` / the cwd `VfsPath.mnt_id`) instead
/// of guessing the containing mount from a bare dentry. The resolution `root`
/// arrives as a bare dentry (the global/chroot root has no dirfd mount context),
/// so its mount id is still derived via `containing_mount_id`. This is the
/// non-lossy replacement for the old "stringify `f.dentry().absolute_path()` →
/// re-walk from cwd" `*at` entry: mount identity is preserved end-to-end and
/// `..` climbs the real mount tree rather than collapsing lexically (D17 / D16).
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_at_cred(
    start: Arc<Dentry>,
    start_mnt_id: u64,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
    cred: Cred,
) -> KResult<VfsPath> {
    let namespace = crate::mount::current_namespace();
    let ns = namespace.id();
    let root_mnt_id = crate::mount::containing_mount_id(ns, &root);
    path_lookup_at_root_cred(start, start_mnt_id, root, root_mnt_id, path, flags, cred)
}

/// As [`path_lookup_at_cred`] but both start and resolution-root carry exact
/// mount ids. Used when callers hold full `struct path` equivalents; re-deriving
/// either id from a bare dentry is ambiguous for bind/pivot clones sharing one
/// superblock root. # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_at_root_cred(
    start: Arc<Dentry>,
    start_mnt_id: u64,
    root: Arc<Dentry>,
    root_mnt_id: u64,
    path: &str,
    flags: LookupFlags,
    cred: Cred,
) -> KResult<VfsPath> {
    let mut nd = Nameidata::new_at(start, start_mnt_id, root, root_mnt_id, flags, cred)?;
    nd.walk(path)
}

/// Resolve a mount syscall target without crossing a mount attached at the
/// final component. Intermediate components use normal mount-aware lookup, so
/// the returned parent carries the exact `vfsmount` identity for attach.
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn mountpoint_lookup_at_root_cred(
    start: Arc<Dentry>,
    start_mnt_id: u64,
    root: Arc<Dentry>,
    root_mnt_id: u64,
    path: &str,
    cred: Cred,
) -> KResult<MountTarget> {
    let final_component = path.rsplit('/').find(|component| !component.is_empty());
    if path == "/" || matches!(final_component, Some(".") | Some("..")) {
        let p = path_lookup_at_root_cred(
            start, start_mnt_id, root, root_mnt_id, path, LookupFlags::default(), cred)?;
        return Ok(mount_target_from_resolved_path(p));
    }
    let parent = path_lookup_at_root_cred(
        start, start_mnt_id, root, root_mnt_id, path,
        LookupFlags { parent: true, ..Default::default() }, cred)?;
    if parent.last_type() != LastType::Norm { return Err(VfsError::Einval); }
    let name = parent.last_component.as_deref().ok_or(VfsError::Einval)?;
    let pi = parent.dentry.inode().ok_or(VfsError::Enoent)?;
    let mountpoint = match crate::d_lookup(&parent.dentry, name) {
        Some(d) if !d.is_negative() => d,
        _ => {
            let ci = pi.lookup(name)?;
            crate::d_add(&parent.dentry, name, ci)
        }
    };
    Ok(MountTarget { parent, mountpoint })
}

/// Convert a resolved `struct path` (for magic fd links such as
/// `/proc/self/fd/N`) into a mount attach target. Linux classic `mount(2)` and
/// `move_mount(2)` operate on the resolved path's `(vfsmount,dentry)` pair; a
/// fd pointing at a mount root is still targeted through that mount, not
/// rewritten to the mount's old parent/mountpoint.
/// # C: O(1)
pub fn mount_target_from_resolved_path(p: VfsPath) -> MountTarget {
    MountTarget { mountpoint: p.dentry.clone(), parent: p }
}
