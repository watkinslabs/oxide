//! Turning a file's compression mark on and off after it exists.
//!
//! The mark is not a preference bit. Setting it commits the file to a cluster
//! width and a codec, and every address the file already holds was written
//! under neither — so the mark and the file's existing blocks cannot both be
//! honoured, and the only file the mark may be added to is one that holds no
//! blocks at all. Clearing it has the mirror problem: the blocks already
//! written ARE clusters, and reading them as plain blocks returns the
//! compressed image as if it were the file.
//!
//! Setting the mark ALSO has to stamp the settings, not just the bit. A file
//! marked compressed with no recorded cluster width claims a width of zero,
//! which is not a width the format admits — this crate's own inode check
//! rejects such an inode, so a mark set without its settings turns a working
//! file into one that cannot be read.

use syscall::errno::Errno;

use crate::flags::{F2FS_COMPR_FL, F2FS_NOCOMP_FL};

/// What the flag word's change means for the file's compression.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FlagChange {
    /// The mark is being added: the settings have to be stamped with it.
    Set,
    /// The mark is being taken away.
    Clear,
    /// The mark is where it was.
    None,
}

/// Everything about the file a decision here reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct FileState {
    pub is_reg: bool,
    pub is_dir: bool,
    /// Whether the file holds any data blocks. A file that does cannot change
    /// how its addresses are grouped.
    pub has_blocks: bool,
    /// Whether the file is held at fixed addresses, or is part way through an
    /// atomic replacement. Either makes a rewrite of its layout impossible.
    pub pinned: bool,
    pub atomic: bool,
}

/// Whether the flag word may move from `held` to `next`, and what that means.
///
/// Order is the contract: a request that trips several clauses reports the
/// first, so the answer does not move when a clause is added.
/// # C: O(1)
pub fn check(feature: u32, held: u32, next: u32, st: &FileState) -> Result<FlagChange, Errno> {
    let asked = next & (F2FS_COMPR_FL | F2FS_NOCOMP_FL);
    // A volume with no compression feature has nowhere to record the settings
    // the mark implies, so the mark would be a claim with nothing behind it.
    // Reported unsupported rather than dropped: a caller that set it and was
    // told nothing would believe the file was compressed.
    if asked != 0 && !crate::features::has_compression(feature) { return Err(Errno::Eopnotsupp); }
    // The two marks answer the same question in opposite directions. Holding
    // both leaves whichever code reads them first deciding, which is not the
    // caller's answer under either reading.
    if asked == F2FS_COMPR_FL | F2FS_NOCOMP_FL { return Err(Errno::Einval); }
    if (held ^ next) & F2FS_COMPR_FL == 0 { return Ok(FlagChange::None); }
    if held & F2FS_COMPR_FL != 0 {
        // The blocks already written ARE clusters; unmarking the file would
        // make the next read hand back the compressed image as file bytes.
        if st.is_reg && st.has_blocks { return Err(Errno::Einval); }
        return Ok(FlagChange::Clear);
    }
    // Only a regular file has clusters and only a directory hands the mark on;
    // on anything else the mark describes nothing.
    if !st.is_reg && !st.is_dir { return Err(Errno::Einval); }
    if st.pinned || st.atomic { return Err(Errno::Einval); }
    // The addresses this file already holds were written one block to one
    // address. Grouping them into clusters after the fact would reinterpret
    // every one of them.
    if st.is_reg && st.has_blocks { return Err(Errno::Einval); }
    Ok(FlagChange::Set)
}

#[cfg(test)]
#[path = "../tests/compress/chattr.rs"]
mod tests;
