extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::KResult;

use super::{Cred, LookupFlags, Nameidata, VfsPath};

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
    let ns = crate::mount::current_ns();
    let root_mnt_id = crate::mount::containing_mount_id(ns, &root);
    let mut nd = Nameidata::new_at(start, start_mnt_id, root, root_mnt_id, flags, cred)?;
    nd.walk(path)
}
