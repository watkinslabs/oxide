//! What refuses a swap area.

use syscall::errno::Errno;

/// Everything the activation decision reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SwapFacts {
    /// The stored type is a regular file.
    pub is_reg: bool,
    /// The mount refuses writes.
    pub ro_mount: bool,
    /// Every write on this mount is out of place, with no in-place path at
    /// all.
    pub lfs_mode: bool,
    /// Segment placement is dictated by the drive's zones.
    pub blkzoned: bool,
    /// The file is compressed and the compression cannot be turned off,
    /// because it already holds compressed blocks.
    pub compressed_undisableable: bool,
}

/// Whether the file may become a swap area.
///
/// The strict-out-of-place refusal is the one that is easy to get backwards:
/// a swap area is written through its addresses forever, so a mount that
/// cannot write in place at all cannot host one — except on zoned storage,
/// where the drive imposes the same rule on everything and the paging code is
/// already dealing with it.
/// # C: O(1)
pub fn swap_activate(f: &SwapFacts) -> Result<(), Errno> {
    if !f.is_reg { return Err(Errno::Einval); }
    if f.ro_mount { return Err(Errno::Erofs); }
    if f.lfs_mode && !f.blkzoned { return Err(Errno::Einval); }
    if f.compressed_undisableable { return Err(Errno::Einval); }
    Ok(())
}
