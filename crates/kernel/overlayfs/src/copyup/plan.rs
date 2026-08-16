//! What kind of copy is needed, and the order its steps run in.
//!
//! The order is stated here as data rather than left implicit in the code that
//! performs it, because it is the part that a test cannot otherwise see: a
//! copy-up whose steps run in the wrong order still produces the right file
//! most of the time, and loses data only on the crash nobody reproduces.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use vfs::types::FileType;

use crate::config::{Config, VerityMode};

/// What is being copied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A regular file whose contents come with it.
    File,
    /// A regular file whose contents stay below, with a record pointing at
    /// them.
    MetaOnly,
    /// A directory: only the directory itself, never its contents.
    Dir,
    /// A symbolic link, recreated with the same target.
    Symlink,
    /// A device node, fifo or socket, recreated with the same device number.
    Special,
}

impl Kind {
    /// What kind of copy an object of this type needs. # C: O(1)
    pub fn of(t: FileType, meta_only: bool) -> Kind {
        match t {
            FileType::Regular if meta_only => Kind::MetaOnly,
            FileType::Regular => Kind::File,
            FileType::Directory => Kind::Dir,
            FileType::Symlink => Kind::Symlink,
            _ => Kind::Special,
        }
    }
    /// Does the copy carry the object's contents? # C: O(1)
    pub fn carries_data(self) -> bool { self == Kind::File }
}

/// One step of a copy-up, in the order it runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Create the object in the work directory, under a name nothing else
    /// uses. Its type and device number are fixed here because they cannot be
    /// changed afterwards.
    CreateTemp,
    /// Copy the contents. FIRST, because writing them clears the file
    /// capabilities that the attribute step is about to restore.
    CopyData,
    /// Copy every attribute the object carries, except the overlay's own.
    CopyXattrs,
    /// Copy the inode flags that a filesystem stores outside the mode word,
    /// and divert the ones that cannot be set on an object still being built.
    CopyFileattr,
    /// Record which lower object this came from, so the two keep one identity.
    SetOrigin,
    /// Record that the contents are still below.
    SetMetacopy,
    /// Set the size, before the attributes, because truncating afterwards
    /// would change the modification time that was just restored.
    SetSize,
    /// Set mode, owner and timestamps.
    SetAttrs,
    /// Flush, when the mount asked for metadata to be durable too.
    Fsync,
    /// Move the finished object into place. LAST: from this instant it is what
    /// every reader sees, so nothing incomplete may reach it.
    MoveIntoPlace,
    /// Restore the destination directory's timestamps, which the move changed.
    RestoreParentTimes,
}

/// The steps a copy-up of `kind` runs, in order.
///
/// `origin` says whether the object's lower identity is being recorded — it is
/// not when a lower hardlink is being broken deliberately. `fsync` follows the
/// mount's durability setting.
/// # C: O(1)
pub fn steps(kind: Kind, origin: bool, fsync: bool) -> Vec<Step> {
    let mut s = vec![Step::CreateTemp];
    if kind.carries_data() { s.push(Step::CopyData); }
    s.push(Step::CopyXattrs);
    if matches!(kind, Kind::File | Kind::MetaOnly | Kind::Dir) { s.push(Step::CopyFileattr); }
    if origin { s.push(Step::SetOrigin); }
    if kind == Kind::MetaOnly { s.push(Step::SetMetacopy); }
    if matches!(kind, Kind::File | Kind::MetaOnly) { s.push(Step::SetSize); }
    s.push(Step::SetAttrs);
    if fsync { s.push(Step::Fsync); }
    s.push(Step::MoveIntoPlace);
    s.push(Step::RestoreParentTimes);
    s
}

/// Does an open with these flags need the object copied up first?
///
/// Only a write does. An open for reading of an object that is still below
/// reads it there, which is what keeps starting a container from copying its
/// whole image.
/// # C: O(1)
pub fn needs_copy_up(open_flags: u32) -> bool {
    open_flags != 0 && (open_flags & O_ACCMODE != O_RDONLY || open_flags & O_TRUNC != 0)
}

/// Access-mode bits of an open flag word.
pub const O_ACCMODE: u32 = 0o3;
/// Open for reading only.
pub const O_RDONLY: u32 = 0;
/// Discard the contents on open.
pub const O_TRUNC: u32 = 0o1000;

/// May this copy-up leave the contents below?
///
/// Never for anything but a regular file, never when the open is going to
/// write anyway, and never when the mount requires a verified digest of the
/// lower data that the lower object cannot supply — in that last case a full
/// copy is the honest answer, since the alternative is an object whose
/// contents the mount promised to verify and cannot.
/// # C: O(1)
pub fn need_meta_copy_up(config: &Config, t: FileType, open_flags: u32, lower_verified: bool)
    -> bool {
    if !config.metacopy { return false; }
    if t != FileType::Regular { return false; }
    if needs_copy_up(open_flags) { return false; }
    if config.verity_mode == VerityMode::Require && !lower_verified { return false; }
    true
}

/// Does this object need an index entry when it is copied up?
///
/// A lower file with several names has to keep them as one file: without an
/// entry recording which upper object it became, the second name copied up
/// would make a second file, and writing through one name would stop being
/// visible through the other.
/// # C: O(1)
pub fn need_index(has_index: bool, index_all: bool, is_dir: bool, nlink: u32) -> bool {
    if !has_index { return false; }
    if index_all { return true; }
    !is_dir && nlink > 1
}

#[cfg(test)]
#[path = "plan/tests.rs"]
mod tests;
