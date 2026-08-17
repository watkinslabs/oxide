//! The file-attribute view: the flag word `chattr` reads and writes.
//!
//! The generic stage owns these commands for every filesystem, so this is not
//! a second dispatcher — it is the pair of decisions that stage asks the
//! filesystem for, kept pure so both are exercised without an inode.
//!
//! Two flag namespaces meet here and they are NOT the same set even where the
//! numbers coincide: the stored inode flags are what the medium holds, and
//! the reported flags add four the medium does not store as flags at all —
//! encrypted, sealed, data-inside-the-inode, and pinned all come from
//! elsewhere in the inode. Reporting the stored word directly would leave a
//! sealed file looking unsealed to every tool that asks.

use syscall::errno::Errno;

use crate::flags::*;

/// Stored flags that also exist in the reported view, where the two
/// namespaces happen to agree on the numbers.
pub const MAPPED: u32 = F2FS_COMPR_FL
    | F2FS_SYNC_FL
    | F2FS_IMMUTABLE_FL
    | F2FS_APPEND_FL
    | F2FS_NODUMP_FL
    | F2FS_NOATIME_FL
    | F2FS_NOCOMP_FL
    | F2FS_INDEX_FL
    | F2FS_DIRSYNC_FL
    | F2FS_PROJINHERIT_FL
    | F2FS_CASEFOLD_FL;

/// Reported flags with no stored flag behind them.
pub const FS_ENCRYPT_FL: u32 = 0x0000_0800;
pub const FS_VERITY_FL: u32 = 0x0010_0000;
pub const FS_INLINE_DATA_FL: u32 = 0x1000_0000;
pub const FS_NOCOW_FL: u32 = 0x0080_0000;

/// Everything a query can report.
pub const GETTABLE: u32 = MAPPED | FS_ENCRYPT_FL | FS_VERITY_FL | FS_INLINE_DATA_FL
    | FS_NOCOW_FL;

/// Everything a set can change. The four derived bits are not among them:
/// each is a consequence of something else about the inode, and letting a
/// caller set one would leave the flag and the thing it describes disagreeing.
pub const SETTABLE: u32 = F2FS_COMPR_FL
    | F2FS_SYNC_FL
    | F2FS_IMMUTABLE_FL
    | F2FS_APPEND_FL
    | F2FS_NODUMP_FL
    | F2FS_NOATIME_FL
    | F2FS_NOCOMP_FL
    | F2FS_DIRSYNC_FL
    | F2FS_PROJINHERIT_FL
    | F2FS_CASEFOLD_FL;

/// Flags that mean nothing on a file that is not a directory.
pub const DIR_ONLY: u32 = F2FS_DIRSYNC_FL | F2FS_PROJINHERIT_FL | F2FS_CASEFOLD_FL;
/// The only two flags anything that is neither a directory nor a regular file
/// may carry.
pub const OTHER_ALLOWED: u32 = F2FS_NODUMP_FL | F2FS_NOATIME_FL;

/// What kind of thing the flags are being applied to, for the mask that
/// depends on it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind { Dir, Reg, Other }

/// Flags legal on `kind`. # C: O(1)
pub fn mask_for(kind: Kind, flags: u32) -> u32 {
    match kind {
        Kind::Dir => flags,
        Kind::Reg => flags & !DIR_ONLY,
        Kind::Other => flags & OTHER_ALLOWED,
    }
}

/// The inode as the flag view reads it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct View {
    pub stored: u32,
    pub encrypted: bool,
    pub verity: bool,
    pub inline_data: bool,
    pub pinned: bool,
}

/// The flag word a query reports.
///
/// Four bits are added that the stored word does not carry, because each
/// describes something the inode says elsewhere and a tool asking "is this
/// sealed" has nowhere else to look.
/// # C: O(1)
pub fn report(v: &View) -> u32 {
    let mut f = v.stored & MAPPED;
    if v.encrypted { f |= FS_ENCRYPT_FL; }
    if v.verity { f |= FS_VERITY_FL; }
    if v.inline_data { f |= FS_INLINE_DATA_FL; }
    if v.pinned { f |= FS_NOCOW_FL; }
    f & GETTABLE
}

/// The stored word a set produces, or the refusal.
///
/// `held` is what the inode carries now; only the settable bits move, so a
/// caller that read the whole reported word and wrote it straight back does
/// not accidentally clear the four derived ones.
/// # C: O(1)
pub fn apply(held: u32, asked: u32, kind: Kind) -> Result<u32, Errno> {
    // A bit nothing reports is a bit this build would silently drop, so the
    // caller is told rather than left believing it was set.
    if asked & !GETTABLE != 0 { return Err(Errno::Eopnotsupp); }
    let want = asked & SETTABLE;
    // A flag that means nothing on this kind of file is refused rather than
    // masked away, so a caller is never told a flag was set that was not.
    if mask_for(kind, want) != want { return Err(Errno::Eopnotsupp); }
    Ok((held & !SETTABLE) | want)
}

#[cfg(test)]
#[path = "../tests/ioctl/fileattr.rs"]
mod tests;
