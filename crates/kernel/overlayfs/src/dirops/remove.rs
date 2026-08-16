//! Unlink and rmdir, and the whiteout that replaces a lower name.
//!
//! Removing a name that exists only in the writable layer is an ordinary
//! removal. Removing one that also exists below cannot be: the lower object
//! stays where it is, and the name has to be covered instead. The cover is
//! itself created in the work directory and exchanged in, so the name is never
//! momentarily absent — a reader that looked in between would see the lower
//! object, which is exactly what was just deleted.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::inode_ops::CreateCtx;
use vfs::namei::RENAME_EXCHANGE;
use vfs::types::{FileType, S_IFCHR};
use vfs::InodeRef;

use crate::err::to_errno;
use crate::layers::{LayerStack, OvlEntry};
use crate::lookup::lookup;
use crate::readdir;
use crate::uapi::WHITEOUT_RDEV;
use crate::whiteout;

use super::plan::needs_whiteout;

/// Would this name still resolve to something after the writable layer's copy
/// is gone?
///
/// Asked by looking, not by trusting the object list: the list may hold a
/// lower object as an IDENTITY (where a copied-up file came from) rather than
/// as a name that is still there, and the two need different answers.
/// # C: O(layers · log n)
pub fn lower_positive(stack: &Arc<LayerStack>, parent: &OvlEntry, name: &str) -> bool {
    for p in &parent.lower {
        if p.layer.data_only { continue; }
        match p.inode.lookup(name) {
            Ok(i) => return !whiteout::is_whiteout(&stack.config, &i, p.layer.xwhiteouts()),
            Err(vfs::VfsError::Enoent) | Err(vfs::VfsError::Enametoolong) => {}
            // Something is there that could not be read. Assuming it is not
            // would make a delete uncover it.
            Err(_) => return true,
        }
    }
    false
}

/// Remove `name` from `parent`.
///
/// A directory is only removed once its merged view is empty; the whiteouts
/// left inside it go with it, since nothing below can be uncovered by removing
/// a directory that is itself about to be covered.
/// # C: O(entries) for a directory, O(1) otherwise
pub fn remove(stack: &Arc<LayerStack>, parent: &OvlEntry, entry: &OvlEntry, name: &str,
              is_dir: bool) -> Result<(), Errno> {
    let Some(dir) = parent.upper.clone() else { return Err(Errno::Erofs) };
    if is_dir && !readdir::is_empty(stack, entry)? { return Err(Errno::Enotempty); }

    let cover = needs_whiteout(lower_positive(stack, parent, name));
    if is_dir {
        if let Some(u) = &entry.upper { clear_whiteouts(stack, u)?; }
    }
    if !cover {
        return match (entry.upper.is_some(), is_dir) {
            (false, _) => Ok(()),
            (true, true) => dir.rmdir(name).map_err(to_errno),
            (true, false) => dir.unlink_child(name).map_err(to_errno),
        };
    }
    cover_with_whiteout(stack, &dir, name, entry.upper.is_some() && is_dir)
}

/// Remove the whiteouts inside a directory that is being removed. # C: O(entries)
fn clear_whiteouts(stack: &Arc<LayerStack>, upper: &InodeRef) -> Result<(), Errno> {
    let list = readdir::merged(stack, &OvlEntry { upper: Some(upper.clone()),
                                                  ..OvlEntry::default() })?;
    for e in readdir::whiteouts(&list) {
        upper.unlink_child(&e.name).map_err(to_errno)?;
    }
    Ok(())
}

/// Put a whiteout at `name`, replacing whatever the writable layer has there.
///
/// The whiteout is created elsewhere and exchanged in, so the name goes
/// straight from the old object to the cover with nothing in between.
/// # C: O(1)
fn cover_with_whiteout(stack: &Arc<LayerStack>, dir: &InodeRef, name: &str, was_dir: bool)
    -> Result<(), Errno> {
    let Some(workdir) = stack.workdir.clone() else { return Err(Errno::Erofs) };
    let tmp = super::create::tempname();
    workdir.mknod_child(&tmp, S_IFCHR, WHITEOUT_RDEV, &CreateCtx::root()).map_err(to_errno)?;

    if dir.lookup(name).is_err() {
        // Nothing of ours is there: the name exists only below, so the cover
        // simply moves in.
        let r = workdir.rename_child(&tmp, dir, name, 0, &CreateCtx::root()).map_err(to_errno);
        if r.is_err() { let _ = workdir.unlink_child(&tmp); }
        return r;
    }

    workdir.rename_child(&tmp, dir, name, RENAME_EXCHANGE, &CreateCtx::root())
        .map_err(|e| { let _ = workdir.unlink_child(&tmp); to_errno(e) })?;
    // The exchange left the removed object in the work directory.
    let _ = if was_dir { workdir.rmdir(&tmp) } else { workdir.unlink_child(&tmp) };
    Ok(())
}

/// Resolve and remove one name under `parent` — the shape the inode operations
/// call. # C: O(entries) for a directory
pub fn remove_name(stack: &Arc<LayerStack>, parent: &OvlEntry, root: &OvlEntry, name: &str,
                   is_dir: bool) -> Result<(), Errno> {
    let Some(entry) = lookup(stack, parent, root, name)? else { return Err(Errno::Enoent) };
    let found_dir = entry.real().map(|i| i.file_type() == FileType::Directory).unwrap_or(false);
    if is_dir && !found_dir { return Err(Errno::Enotdir); }
    if !is_dir && found_dir { return Err(Errno::Eisdir); }
    remove(stack, parent, &entry, name, is_dir)
}
