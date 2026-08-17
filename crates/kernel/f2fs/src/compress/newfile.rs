//! Whether a file being CREATED is created compressed.
//!
//! Nothing later can answer this. A file's codec, cluster width and checksum
//! request are stamped once, at creation, and every stored address is read
//! back under the width that was stamped — so a file created plain stays
//! plain, and a file created compressed cannot be reinterpreted afterwards.
//!
//! Three inputs decide it and they are consulted in a fixed order, because
//! each later one is only reached when the earlier ones said nothing:
//!
//! 1. **The volume's own hot list.** A name whose data is rewritten often is
//!    left alone: a single changed block inside a compressed cluster costs
//!    the whole cluster, so compressing those trades space for a write
//!    amplification the volume was formatted to avoid.
//! 2. **The mount's two extension lists.** The refusing list is consulted
//!    first and STOPS there — a name it names takes nothing from its
//!    directory either, which is what makes `compress_extension=*` with a
//!    handful of refusals a usable pair.
//! 3. **The directory.** A name neither list mentions inherits whichever mark
//!    its parent carries, so a tree can be marked once instead of by name.
//!
//! The name is the one the CREATING OPERATION handed over, which is not the
//! same as the name the directory entry gets. Only ordinary file creation
//! supplies one: a device node, a symbolic link and an unnamed temporary file
//! are created without a name and take compression from neither their name
//! nor their directory. A directory skips the name entirely and goes straight
//! to inheritance, since a directory holds no data of its own to compress.

use crate::flags::{F2FS_COMPR_FL, F2FS_NOCOMP_FL};
use crate::opts::compress::ExtList;

use super::policy::{matches_extension, matches_temperature_extension};

/// What a new inode's creation does about compression.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NewFile {
    /// Stamp the mount's codec, width and checksum request onto it.
    Compress,
    /// Mark it one that must never be compressed, so a later blanket rule
    /// over the tree cannot pick it up.
    Refuse,
    /// Leave it as it was built.
    Plain,
}

/// The decision for one new inode. # C: O(names * lengths)
pub fn decide(is_dir: bool, name: Option<&[u8]>, hot: &[&[u8]], dir_flags: u32,
              allow: &ExtList, refuse: &ExtList) -> NewFile {
    if !is_dir {
        let Some(name) = name else { return NewFile::Plain };
        if hot.iter().any(|e| matches_temperature_extension(name, e)) { return NewFile::Plain; }
        if refuse.iter().any(|e| matches_extension(name, e)) { return NewFile::Plain; }
        if allow.iter().any(|e| matches_extension(name, e)) { return NewFile::Compress; }
    }
    inherit(dir_flags)
}

/// What the parent directory's own marks say.
///
/// The refusal wins over the request, and it is the only one of the two that
/// is COPIED: a directory marked as compressing hands its children the
/// mount's current settings rather than its own, because the settings are not
/// recorded on a directory at all.
/// # C: O(1)
fn inherit(dir_flags: u32) -> NewFile {
    if dir_flags & F2FS_NOCOMP_FL != 0 { return NewFile::Refuse; }
    if dir_flags & F2FS_COMPR_FL != 0 { return NewFile::Compress; }
    NewFile::Plain
}

#[cfg(test)]
#[path = "../tests/compress/newfile.rs"]
mod tests;
