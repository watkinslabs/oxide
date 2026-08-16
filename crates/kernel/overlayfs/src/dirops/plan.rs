//! The decisions each directory operation turns on.
//!
//! These are the parts that are easy to get subtly wrong and hard to see
//! afterwards: whether a delete needs a whiteout, whether a rename may proceed
//! at all, and which rename flags carry it out. Each is a function of what the
//! layers hold, so each fails a test without a mount.

use crate::config::Config;
use crate::layers::PathType;

/// Does removing this name need a whiteout left behind?
///
/// Only when the name would still resolve to something below afterwards.
/// Leaving one where nothing is below costs an object in the writable layer
/// and makes a later `rmdir` of the parent fail; omitting one where something
/// IS below makes a deleted file come back.
/// # C: O(1)
pub fn needs_whiteout(lower_positive: bool) -> bool { lower_positive }

/// May this object be renamed?
///
/// A directory that merges, or that exists only below, cannot move: its lower
/// half stays where it is. It can only be renamed when the mount writes a
/// record of where that half lives. Everything else — a file, or a directory
/// that is purely in the writable layer — moves freely.
/// # C: O(1)
pub fn can_move(config: &Config, is_dir: bool, t: PathType) -> bool {
    if !is_dir { return true; }
    if config.redirect_dir() { return true; }
    !(t.merge || !t.upper)
}

/// Rename flags, and the cleanup that follows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RenamePlan {
    /// Leave a whiteout where the source name was.
    pub whiteout: bool,
    /// Swap the two names rather than replacing one with the other.
    pub exchange: bool,
    /// After the swap, remove what came back to the source name.
    pub cleanup: bool,
}

/// Work out how to carry out a rename in the writable layer.
///
/// The source needs a whiteout whenever the name still resolves below after
/// the move. When the destination is ALREADY a whiteout, the two are exchanged
/// instead: that both puts the object in place and leaves a whiteout behind,
/// in one step that cannot be interrupted half-done.
/// # C: O(1)
pub fn rename_plan(exchange_requested: bool, source_over_lower: bool, dest_is_whiteout: bool,
                   source_is_dir: bool) -> RenamePlan {
    if exchange_requested { return RenamePlan { exchange: true, ..RenamePlan::default() }; }
    if source_over_lower {
        if dest_is_whiteout { RenamePlan { exchange: true, ..RenamePlan::default() } }
        else { RenamePlan { whiteout: true, ..RenamePlan::default() } }
    } else if source_is_dir && dest_is_whiteout {
        // Nothing has to be left behind, but the whiteout coming back to the
        // source name is not wanted there, so it is removed afterwards.
        RenamePlan { exchange: true, cleanup: true, ..RenamePlan::default() }
    } else {
        RenamePlan::default()
    }
}

/// Does a newly created directory need to be opaque?
///
/// Only where a lower directory of the same name could otherwise show through:
/// over a whiteout, whose whole purpose was to hide one, and in a merged
/// parent on a mount whose features already forbid changing the layers
/// underneath it.
/// # C: O(1)
pub fn new_dir_opaque(config: &Config, over_whiteout: bool, parent_merges: bool) -> bool {
    over_whiteout || (parent_merges && !config.allow_offline_changes())
}

/// Are these rename flags ones this filesystem can carry out? # C: O(1)
pub fn rename_flags_ok(flags: u32) -> bool {
    flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) == 0
}

/// Refuse to replace an existing destination.
pub const RENAME_NOREPLACE: u32 = vfs::namei::RENAME_NOREPLACE;
/// Swap two names.
pub const RENAME_EXCHANGE: u32 = vfs::namei::RENAME_EXCHANGE;
/// Leave a whiteout where the source was.
pub const RENAME_WHITEOUT: u32 = vfs::namei::RENAME_WHITEOUT;

#[cfg(test)]
#[path = "plan/tests.rs"]
mod tests;
