//! Moving a name, and what has to be recorded for it to survive.
//!
//! A rename inside the writable layer is one operation on one filesystem, so
//! it is atomic — but only the writable half moves. Two things follow. The
//! source name may still resolve below, so it needs a whiteout, and the flag
//! that leaves one is part of the SAME rename rather than a second step. And a
//! directory that merges leaves its lower half behind entirely, so its new
//! upper half has to record where that half lives, or the move is refused with
//! `EXDEV` and the caller copies the tree by hand.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::types::FileType;

use crate::err::to_errno;
use crate::layers::{LayerStack, OvlEntry};
use crate::marker;
use crate::redirect;
use crate::uapi::Marker;
use crate::whiteout;

use super::plan::{can_move, rename_flags_ok, rename_plan, RENAME_EXCHANGE, RENAME_NOREPLACE,
                  RENAME_WHITEOUT};
use super::remove::lower_positive;

/// Move `old_name` in `old_parent` to `new_name` in `new_parent`.
///
/// Both source and destination parents must already exist in the writable
/// layer, and the source object must already have been copied up — the caller
/// does that, because it also has to copy up the ancestors.
///
/// `src_path` is the SOURCE's path from the mount root, which is where its
/// lower half still is — the record has to name that, and it can only be built
/// before the move.
/// # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn rename(stack: &Arc<LayerStack>, old_parent: &OvlEntry, old_name: &str,
              old_entry: &OvlEntry, new_parent: &OvlEntry, new_name: &str,
              new_entry: Option<&OvlEntry>, flags: u32, src_path: &[&str])
    -> Result<(), Errno> {
    if !rename_flags_ok(flags) { return Err(Errno::Einval); }
    let (Some(od), Some(nd)) = (old_parent.upper.clone(), new_parent.upper.clone())
        else { return Err(Errno::Erofs) };
    let exchange = flags & RENAME_EXCHANGE != 0;
    if flags & RENAME_NOREPLACE != 0 && new_entry.is_some() { return Err(Errno::Eexist); }

    let is_dir = old_entry.real().map(|i| i.file_type() == FileType::Directory).unwrap_or(false);
    if !can_move(&stack.config, is_dir, old_entry.path_type(is_dir)) { return Err(Errno::Exdev); }
    if exchange {
        if let Some(ne) = new_entry {
            let nd_is_dir = ne.real().map(|i| i.file_type() == FileType::Directory)
                .unwrap_or(false);
            if !can_move(&stack.config, nd_is_dir, ne.path_type(nd_is_dir)) {
                return Err(Errno::Exdev);
            }
        }
    }

    let dest_is_whiteout = nd.lookup(new_name).ok()
        .is_some_and(|i| whiteout::is_whiteout(&stack.config, &i, true));
    let plan = rename_plan(exchange, lower_positive(stack, old_parent, old_name),
                           dest_is_whiteout, is_dir);

    // A directory whose lower half stays behind records where it is BEFORE the
    // move, because after it the old name is gone and the record could not be
    // derived any more.
    let samedir = core::ptr::eq(old_parent as *const OvlEntry, new_parent as *const OvlEntry)
        || old_parent.upper.as_ref().zip(new_parent.upper.as_ref())
            .is_some_and(|(a, b)| Arc::ptr_eq(a, b));
    if is_dir && old_entry.has_lower() {
        set_redirect(stack, old_entry, src_path, need_absolute(samedir, true, 1))?;
    }

    let mut real = 0u32;
    if plan.exchange { real |= RENAME_EXCHANGE; }
    if plan.whiteout { real |= RENAME_WHITEOUT; }
    stack.with_access_ctx(|ctx| od.rename_child(old_name, &nd, new_name, real, ctx)).map_err(to_errno)?;

    if plan.cleanup {
        // The exchange sent the destination's whiteout back to the source
        // name, where nothing needs covering.
        let _ = stack.with_access_ctx(|ctx| od.unlink_child_with_ctx(old_name, ctx));
    }
    Ok(())
}

/// Record where a renamed directory's lower half lives.
///
/// A path from the layer root is used whenever the directory moved between
/// parents, because a name alone would be resolved in the wrong one.
/// # C: O(depth)
fn set_redirect(stack: &Arc<LayerStack>, entry: &OvlEntry, path: &[&str], absolute: bool)
    -> Result<(), Errno> {
    let Some(upper) = &entry.upper else { return Ok(()) };
    if !stack.config.redirect_dir() { return Err(Errno::Exdev); }
    let existing = entry.redirect.clone();
    if redirect::still_valid(existing.as_ref(), absolute) { return Ok(()); }
    let value = redirect::build(path, absolute)?;
    match marker::set(&stack.config, upper, Marker::Redirect, value.as_str().as_bytes(),
                      Errno::Exdev) {
        Ok(()) => Ok(()),
        // A layer that will not hold the record cannot carry the move; saying
        // so lets the caller copy the tree instead of losing its lower half.
        Err(_) => Err(Errno::Exdev),
    }
}

/// Does the record have to name a path from the layer root rather than a
/// single name?
///
/// Always when the object changed parents, because a bare name would be
/// resolved in the wrong one. Never for a directory that stayed put. For a
/// non-directory with several names below, always: two of its upper names may
/// end up in different directories, and one relative record cannot serve both.
/// # C: O(1)
pub fn need_absolute(samedir: bool, is_dir: bool, lower_nlink: u32) -> bool {
    if !samedir { return true; }
    if is_dir { return false; }
    lower_nlink > 1
}

/// The path components of a destination, as the record wants them: each
/// ancestor's own recorded value where it has one, else its name. # C: O(depth)
pub fn redirect_path(names: &[String], recorded: &[Option<String>]) -> Vec<String> {
    names.iter().enumerate()
        .map(|(i, n)| recorded.get(i).and_then(|r| r.clone()).unwrap_or_else(|| n.to_string()))
        .collect()
}
