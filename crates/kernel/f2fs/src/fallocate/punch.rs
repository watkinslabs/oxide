//! `PUNCH_HOLE`: the range reads as zeroes and stops costing blocks.
//!
//! Whole blocks inside the range are freed; the partial blocks at each end are
//! not, because their other half still holds data. Those are zeroed in place
//! instead, which is why a punch of a few bytes can COST a block: the byte
//! range asked for is not a block boundary, and the block has to exist to hold
//! the half that is staying.
//!
//! The file's length never changes. A punch at the end leaves the size where
//! it was and the tail reading as zeroes, which is the whole difference between
//! this and shortening.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Free what `[offset, offset + len)` of `ino` holds. # C: O(blocks freed)
    pub(crate) fn punch_hole(&mut self, ino: u32, offset: u64, len: u64) -> Result<(), Errno> {
        // A file living inside its inode has no blocks to free, and the range
        // is inside the address array. It moves out first, so the punch has
        // blocks to act on and cannot reach the array by mistake.
        self.convert_inline(ino)?;
        let blk = BLKSIZE as u64;
        let end = offset + len;
        let mut first = offset / blk;
        let last = end / blk;
        let head = (offset % blk) as usize;
        let tail = (end % blk) as usize;
        if first == last {
            // Wholly inside one block: nothing is freed and the bytes are
            // zeroed where they sit — which can still COST a block, because a
            // range inside a hole has to have one to hold the zeroes.
            self.fill_zero(ino, first, head, tail - head)?;
        } else {
            if head != 0 {
                self.fill_zero(ino, first, head, BLKSIZE - head)?;
                first += 1;
            }
            if tail != 0 { self.fill_zero(ino, last, 0, tail)?; }
            if first < last { self.truncate_hole(ino, first, last)?; }
        }
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))
    }
}
