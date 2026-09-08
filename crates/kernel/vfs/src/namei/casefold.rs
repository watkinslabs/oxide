//! Case-insensitive resolution of one path component.
//!
//! A Windows path names a file without regard to case, and the filesystems the
//! guest actually runs on store one exact spelling and compare it byte for
//! byte. A filesystem that carries its own case-folding index answers the
//! lookup itself; for every other one the resolution is a scan of the
//! directory for the entry whose stored spelling folds to the wanted name,
//! which is what a Windows personality does on a case-sensitive host.
//!
//! The scan runs only after an exact lookup has already missed, so a correctly
//! spelled path never pays for it.

use alloc::string::{String, ToString};
use crate::file_ops::{DirContext, DirEmit};
use crate::inode::Inode;
use crate::types::FileType;

/// Upper bound on entries scanned for one component. A directory larger than
/// this resolves only by exact spelling rather than holding the walk.
const MAX_SCANNED_ENTRIES: u64 = 64 * 1024;

/// Whether two names are the same under simple case folding. Neither side is
/// allocated: the comparison walks both in one pass.
/// # C: O(name length)
pub(crate) fn names_fold_equal(left: &str, right: &str) -> bool {
    let mut left = left.chars().flat_map(char::to_lowercase);
    let mut right = right.chars().flat_map(char::to_lowercase);
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (a, b) if a != b => return false,
            _ => {}
        }
    }
}

/// Collects the stored spelling of the first entry matching under case folding.
struct MatchingName<'a> {
    wanted: &'a str,
    found: Option<String>,
    scanned: u64,
}

impl DirEmit for MatchingName<'_> {
    fn emit(&mut self, name: &str, _ino: u64, _d_type: FileType, _next_pos: u64) -> bool {
        self.scanned += 1;
        // An exact spelling already missed, so an entry equal to the wanted
        // name cannot be the one being resolved; skipping it also keeps the
        // scan from answering with a name the caller already tried.
        if name != self.wanted && names_fold_equal(name, self.wanted) {
            self.found = Some(name.to_string());
            return false;
        }
        self.scanned < MAX_SCANNED_ENTRIES
    }
}

/// Whether a component may be resolved by folding at all. The empty name and
/// the two directory entries the walk owns itself are never resolved by a
/// scan: they have exactly one spelling, and an exact lookup has already
/// answered for them.
/// # C: O(1)
pub(crate) fn resolvable_component(wanted: &str) -> bool {
    !wanted.is_empty() && wanted != "." && wanted != ".."
}

/// The stored spelling of `wanted` in `dir`, or `None` when the directory has
/// no entry equal to it under case folding.
/// # C: O(directory entries)
pub(crate) fn stored_name(dir: &Inode, wanted: &str) -> Option<String> {
    if !resolvable_component(wanted) { return None; }
    let mut actor = MatchingName { wanted, found: None, scanned: 0 };
    let mut ctx = DirContext::new(0, &mut actor);
    let _ = dir.readdir(&mut ctx);
    actor.found
}

#[cfg(test)]
#[path = "casefold/tests.rs"]
mod tests;
