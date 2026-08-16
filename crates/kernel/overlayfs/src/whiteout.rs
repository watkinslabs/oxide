//! How a deleted lower name is recorded, and recognised.
//!
//! Deleting a file that exists only in a read-only layer cannot remove it, so
//! the upper layer gets an object in its place whose only job is to say "there
//! is nothing here". Getting the recognition wrong in either direction is
//! severe: an unrecognised whiteout makes a deleted file reappear, and a
//! misrecognised ordinary object makes a real file vanish.
//!
//! Two forms exist. The original is a character device with device number
//! zero, which no real device has. Layers that cannot hold device nodes — an
//! unprivileged extraction of a container layer, most obviously — use an empty
//! regular file carrying a marker instead, and a directory known to contain
//! those is flagged so the slower check is only made where it can pay off.

extern crate alloc;

use vfs::types::FileType;
use vfs::Inode;

use crate::config::Config;
use crate::marker;
use crate::uapi::{Marker, WHITEOUT_RDEV};

/// The original form: a character device with device number zero. # C: O(1)
pub fn is_device(inode: &Inode) -> bool {
    inode.file_type() == FileType::CharDev && inode.rdev() == WHITEOUT_RDEV
}

/// The marker form: an EMPTY REGULAR FILE carrying the whiteout marker.
///
/// Both the type and the zero size are part of the test. A non-empty file with
/// the marker is a real file whose owner happened to set the attribute, and
/// treating it as a whiteout would hide it and everything below it.
/// # C: O(log n)
pub fn is_marked(config: &Config, inode: &Inode) -> bool {
    if inode.file_type() != FileType::Regular || inode.size() != 0 { return false; }
    marker::present(config, inode, Marker::Xwhiteout)
}

/// Is this object a whiteout in either form?
///
/// The marker form is only consulted when the directory it was found in is
/// known to contain them, because the check costs an attribute read on every
/// name in every layer otherwise.
/// # C: O(1), or O(log n) in a directory carrying marker whiteouts
pub fn is_whiteout(config: &Config, inode: &Inode, in_marked_dir: bool) -> bool {
    is_device(inode) || (in_marked_dir && is_marked(config, inode))
}

/// What an opaque marker on a directory says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Opacity {
    /// Ordinary directory: it merges with the same name in lower layers.
    Merge,
    /// Nothing below this name is visible; the directory replaced a lower one.
    Opaque,
    /// Merges, but may contain whiteouts written as marked regular files.
    MarkedWhiteouts,
}

/// Read a directory's opaque marker.
///
/// The `x` value is deliberately NOT opacity: a layer that cannot hold device
/// nodes needs somewhere to say that it uses the marker form, and reusing this
/// attribute's value avoids a second attribute read on every directory. An
/// older kernel that does not know `x` reads it as "not `y`" and merges, which
/// is the safe direction — it shows files a newer kernel would hide, rather
/// than hiding files that are there.
/// # C: O(log n)
pub fn opacity(config: &Config, inode: &Inode) -> Opacity {
    match marker::dir_val(config, inode, Marker::Opaque) {
        b'y' => Opacity::Opaque,
        b'x' => Opacity::MarkedWhiteouts,
        _ => Opacity::Merge,
    }
}

/// Does this directory hide every lower directory of the same name? # C: O(log n)
pub fn is_opaque(config: &Config, inode: &Inode) -> bool {
    opacity(config, inode) == Opacity::Opaque
}

/// Does this directory hold entries whose lower origin is not their name, so
/// that a merged read has to resolve each one? # C: O(log n)
pub fn is_impure(config: &Config, inode: &Inode) -> bool {
    marker::dir_val(config, inode, Marker::Impure) == b'y'
}

#[cfg(test)]
#[path = "whiteout/tests.rs"]
mod tests;
