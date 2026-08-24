//! The `fallocate(2)` slot, and the swap-area hooks a paging area needs.
//!
//! Everything the five requests do is decided and tested below `Volume`; this
//! is the adapter that reaches them from the interface. It exists as its own
//! module because the generic layer hands the RAW mode word down — the vetting
//! it has already done is the combination gate, not this filesystem's own
//! refusals — so the slot has to say which of its answers come from where.

use vfs::{Inode, KResult};

use super::ops::F2fsOps;
use super::errno_to_vfs;
use super::write::now;

/// `f2fs_fallocate` — serve one request on the file `inode` names.
///
/// The refusal ladder, the dispatch by mode and the block work are all
/// `Volume::fallocate`'s. What belongs here is what the reference does around
/// its own dispatch and nowhere else: the pair of timestamps a successful
/// allocation moves, and putting the file's new length and block count back
/// onto the cached inode. Both stamps are written to the medium as well as the
/// cached inode, because the reference marks the inode dirty rather than
/// leaving the change in memory.
/// # C: O(blocks the range covers)
pub(super) fn fallocate(inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
    let node = F2fsOps::node(inode)?;
    let stamp = now();
    {
        let mut v = node.fs.volume.lock();
        v.fallocate(node.ino, mode, off, len).map_err(errno_to_vfs)?;
    }
    node.restat(inode)?;
    let ts = vfs::timespec::Timespec64 { sec: stamp.0 as i64, nsec: stamp.1 };
    inode.update_time(ts, vfs::S_MTIME | vfs::S_CTIME)
}

#[cfg(test)]
#[path = "../tests/falloc_wire.rs"]
mod tests;
