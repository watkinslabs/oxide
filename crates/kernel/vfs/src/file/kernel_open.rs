//! Opening a file from inside the kernel (Linux `filp_open` / `file_open_root`).
//!
//! An in-kernel opener resolves a pathname, optionally creates the leaf, and
//! gets back a live `struct file` it writes through — the same object and the
//! same sequence a descriptor-returning open produces, minus the descriptor.
//! It exists so kernel-side writers do not reach past the open path and create
//! through a directory inode: that leaves the name unpublished, and the object
//! is then written and unreachable.
//!
//! `root` is supplied by the caller rather than taken from the running task,
//! because the callers that need this are writing on behalf of a process whose
//! namespace is the one that must be walked.

use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode_ops::CreateCtx;
use crate::namei::{path_lookup_at_root_cred, vfs_create_at, Cred, LookupFlags, VfsPath};
use crate::types::{FileType, KResult, OpenFlags, VfsError};

use super::{File, FileCred};

/// Split an absolute pathname into the directory to look up and the leaf to
/// open in it. `None` when the path names no final component.
fn split_parent(path: &str) -> Option<(&str, &str)> {
    if !path.starts_with('/') { return None; }
    let cut = path.rfind('/')?;
    let name = &path[cut + 1..];
    if name.is_empty() || name == "." || name == ".." { return None; }
    Some((if cut == 0 { "/" } else { &path[..cut] }, name))
}

/// Resolve `dir` as a directory, refusing to follow a symlink at the end of it.
fn lookup_dir(root: &Arc<Dentry>, root_mnt: u64, dir: &str, cred: &Cred) -> KResult<VfsPath> {
    let flags = LookupFlags { no_follow_final: true, ..LookupFlags::default() };
    let vp = path_lookup_at_root_cred(
        Arc::clone(root), root_mnt, Arc::clone(root), root_mnt, dir, flags, cred.clone())?;
    if vp.inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
    Ok(vp)
}

/// Open `path` under `root`, creating the leaf when `O_CREAT` is set.
///
/// Honours the flags an in-kernel opener actually needs and refuses the rest
/// rather than ignoring them: `O_CREAT`, `O_EXCL`, `O_NOFOLLOW`, `O_TRUNC` and
/// the access mode. The leaf is never followed through a symlink — an internal
/// writer resolving a link it did not place is how a caller-chosen pathname
/// redirects a kernel write.
///
/// `mode` applies only to a create. `cred` is whose permission the walk and the
/// create are checked against, and whose ownership a created object takes.
/// # C: O(path components) + backend open
pub fn kernel_open_at_root(
    root: &Arc<Dentry>, root_mnt: u64, path: &str, flags: OpenFlags, mode: u32, cred: Cred,
) -> KResult<Arc<File>> {
    let (dir, name) = split_parent(path).ok_or(VfsError::Einval)?;
    let parent = lookup_dir(root, root_mnt, dir, &cred)?;

    // Look the leaf up in the parent that was just resolved, never following it:
    // Linux's `O_NOFOLLOW` on the final component, which an internal open always
    // wants.
    let leaf_flags = LookupFlags { no_follow_final: true, ..LookupFlags::default() };
    let existing = path_lookup_at_root_cred(
        Arc::clone(root), root_mnt, parent.dentry.clone(), parent.mnt_id, name, leaf_flags, cred.clone());

    let (inode, dentry) = match existing {
        Ok(vp) => {
            if flags.contains(OpenFlags::O_CREAT) && flags.contains(OpenFlags::O_EXCL) {
                return Err(VfsError::Eexist);
            }
            if vp.inode.file_type() == FileType::Symlink { return Err(VfsError::Eloop); }
            (vp.inode, vp.dentry)
        }
        Err(e) => {
            if !flags.contains(OpenFlags::O_CREAT) { return Err(e); }
            let ctx = CreateCtx { idmap: &crate::idmap::IDENTITY, cred: &cred, umask: 0 };
            vfs_create_at(&parent, name, mode, &ctx)?
        }
    };

    let fcred = FileCred::new(cred, namespace_identity::initial(
        namespace_identity::NamespaceKind::User), u64::MAX);
    super::open::open_file_at(inode, dentry, flags, parent.mnt_id, fcred, None)
}
