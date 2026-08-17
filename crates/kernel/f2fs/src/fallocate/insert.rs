//! `INSERT_RANGE`: open a gap at a point and move everything after it along.
//!
//! The mirror image of collapsing, and aligned for the same reason: every byte
//! after the point keeps its value at a HIGHER offset, which is only a move of
//! whole blocks when both ends fall on block boundaries. The gap that opens is
//! a hole — no blocks are allocated for it, so inserting into a sparse file
//! costs nothing but the moves.
//!
//! An offset at or past the end is refused. There is nothing after it to move,
//! so the request is an ordinary extension and has an ordinary way to be asked
//! for.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Open a gap of `len` at `offset` in `ino`. # C: O(blocks after the point)
    pub(crate) fn insert_range(&mut self, ino: u32, offset: u64, len: u64)
        -> Result<(), Errno> {
        let size = self.read_inode(ino)?.size;
        let new_size = size.checked_add(len).ok_or(Errno::Efbig)?;
        self.newsize_ok(ino, new_size)?;
        if offset >= size { return Err(Errno::Einval); }
        let blk = BLKSIZE as u64;
        if offset % blk != 0 || len % blk != 0 { return Err(Errno::Einval); }
        self.convert_inline(ino)?;
        let start = offset / blk;
        let delta = len / blk;
        let blocks = size.div_ceil(blk);
        // Upwards, so a block is never written over one that has not moved.
        self.move_run_up(ino, start, start + delta, blocks - start)?;
        let count = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| {
            crate::volume::dnode::put64(b, I_SIZE, new_size);
            Self::set_iblocks(b, count);
        })
    }
}
