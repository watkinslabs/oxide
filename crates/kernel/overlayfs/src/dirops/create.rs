//! Creating a name in the writable layer.
//!
//! Two cases. Where nothing is in the way the object is created directly. Where
//! a WHITEOUT stands — the name was deleted from a lower layer earlier — the
//! new object is built in the work directory and exchanged with the whiteout,
//! because replacing the whiteout in place would, if interrupted, leave the
//! lower object visible again under a name that was supposed to be new.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::namei::RENAME_EXCHANGE;
use vfs::types::{FileType, S_IFDIR, S_IFMT};
use vfs::InodeRef;

use crate::err::to_errno;
use crate::layers::{LayerStack, OvlEntry};
use crate::marker;
use crate::uapi::{Marker, MARKER_YES};
use crate::whiteout;

use super::plan::new_dir_opaque;

/// What is being created.
#[derive(Clone)]
pub enum New {
    /// A regular file with these permission bits.
    File(u32),
    /// A directory.
    Dir(u32),
    /// A device node, fifo or socket: full mode word and device number.
    Node(u32, u32),
    /// A symbolic link with this target.
    Symlink(alloc::vec::Vec<u8>),
    /// Another name for an object already in the writable layer.
    Hardlink(InodeRef),
}

/// Create `name` under `parent`, which must already exist in the writable
/// layer.
///
/// `parent_merges` says whether the parent still has lower halves, which
/// decides whether a new directory has to hide them.
/// # C: O(1)
pub fn create(stack: &Arc<LayerStack>, parent: &OvlEntry, name: &str, what: New,
              parent_merges: bool) -> Result<InodeRef, Errno> {
    let Some(dir) = parent.upper.clone() else { return Err(Errno::Erofs) };
    let existing = dir.lookup(name).ok();
    let over_whiteout = existing.as_ref()
        .is_some_and(|i| whiteout::is_whiteout(&stack.config, i, true));
    if existing.is_some() && !over_whiteout { return Err(Errno::Eexist); }

    if !over_whiteout {
        let made = make(stack, &dir, name, &what)?;
        if matches!(what, New::Dir(_)) && new_dir_opaque(&stack.config, false, parent_merges) {
            // Best effort: a layer that will not hold the marker still gives a
            // correct merge, just a slower one.
            let _ = marker::set(&stack.config, &made, Marker::Opaque, MARKER_YES, Errno::Eio);
        }
        return Ok(made);
    }

    let Some(workdir) = stack.workdir.clone() else { return Err(Errno::Erofs) };
    let tmp = crate::copyup::run::tempname();
    let made = make(stack, &workdir, &tmp, &what)?;
    if matches!(what, New::Dir(_)) {
        // The whiteout it replaces was hiding a lower directory; without this
        // the lower one would merge into the new one.
        marker::set(&stack.config, &made, Marker::Opaque, MARKER_YES, Errno::Eio)?;
    }
    stack.with_access_ctx(|ctx| workdir.rename_child(&tmp, &dir, name, RENAME_EXCHANGE, ctx))
        .map_err(to_errno)?;
    // The exchange put the whiteout in the work directory; it has done its job.
    let _ = stack.with_access_ctx(|ctx| workdir.unlink_child_with_ctx(&tmp, ctx));
    dir.lookup(name).map_err(to_errno)
}

/// Create one object in one real directory. # C: O(1)
fn make(stack: &Arc<LayerStack>, dir: &InodeRef, name: &str, what: &New) -> Result<InodeRef, Errno> {
    stack.with_access_ctx(|ctx| match what {
        New::File(mode) => dir.create_child(name, *mode, ctx).map_err(to_errno),
        New::Dir(mode) => dir.mkdir(name, mode | S_IFDIR as u32, ctx).map_err(to_errno),
        New::Node(mode, rdev) => {
            dir.mknod_child(name, *mode as u16, *rdev, ctx).map_err(to_errno)?;
            dir.lookup(name).map_err(to_errno)
        }
        New::Symlink(target) => {
            dir.symlink_child(name, target, ctx).map_err(to_errno)?;
            dir.lookup(name).map_err(to_errno)
        }
        New::Hardlink(target) => {
            dir.link_child(target, name, ctx).map_err(to_errno)?;
            dir.lookup(name).map_err(to_errno)
        }
    })
}

/// Refuse to create the object that stands for a deleted name.
///
/// A caller inside the overlay must not be able to make one by hand: it would
/// make an arbitrary lower file disappear, which is not a thing `mknod` may do.
/// # C: O(1)
pub fn creating_whiteout_refused(mode: u32, rdev: u32) -> bool {
    mode & S_IFMT as u32 == vfs::types::S_IFCHR as u32 && rdev == crate::uapi::WHITEOUT_RDEV
}

/// Add another name for `target` under `parent`. # C: O(1)
pub fn link(stack: &Arc<LayerStack>, parent: &OvlEntry, name: &str, target: &InodeRef,
            parent_merges: bool) -> Result<InodeRef, Errno> {
    if target.file_type() == FileType::Directory { return Err(Errno::Eperm); }
    create(stack, parent, name, New::Hardlink(target.clone()), parent_merges)
}

/// Mark a directory as holding entries whose lower origin is not their name,
/// so a merged read resolves each one rather than trusting the name. # C: O(1)
pub fn set_impure(stack: &Arc<LayerStack>, dir: &InodeRef) -> Result<(), Errno> {
    if whiteout::is_impure(&stack.config, dir) { return Ok(()); }
    // Not fatal: without the marker the merge is still correct, only the
    // reported inode numbers of copied-up entries may be the upper ones.
    let _ = marker::set(&stack.config, dir, Marker::Impure, MARKER_YES, Errno::Eio);
    Ok(())
}

/// A name in the work directory, exposed so create and copy-up mint them the
/// same way. # C: O(1)
pub fn tempname() -> String { crate::copyup::run::tempname() }
