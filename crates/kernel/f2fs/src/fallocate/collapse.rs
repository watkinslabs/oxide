//! `COLLAPSE_RANGE`: take a range out and close the gap.
//!
//! The file gets shorter by exactly the length removed, and every byte after
//! the range keeps its value at a lower offset. That is only expressible in
//! whole blocks — a byte-granular collapse would have to rewrite the contents
//! of every block after the point rather than move it — so both ends must be
//! block-aligned, and a range reaching the end of the file is refused because
//! that is shortening, which has its own call.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Remove `[offset, offset + len)` from `ino` and close the gap.
    /// # C: O(blocks after the range)
    pub(crate) fn collapse_range(&mut self, ino: u32, offset: u64, len: u64)
        -> Result<(), Errno> {
        let size = self.read_inode(ino)?.size;
        // A range reaching the end is a truncation wearing a different name,
        // and answering it here would leave two calls that shorten a file with
        // different rules about what they refuse.
        if offset + len >= size { return Err(Errno::Einval); }
        let blk = BLKSIZE as u64;
        if offset % blk != 0 || len % blk != 0 { return Err(Errno::Einval); }
        self.convert_inline(ino)?;
        let start = offset / blk;
        let end = (offset + len) / blk;
        // One past the last block the file has, which is how many there are to
        // move down: the tail may be partial and still has to travel.
        let blocks = size.div_ceil(blk);
        self.move_run_down(ino, end, start, blocks - end)?;
        let new_size = size - len;
        // The tail nodes are freed once the moves are done: everything from
        // the new end onwards is now a duplicate of what moved down.
        self.truncate_tail(ino, new_size.div_ceil(blk))?;
        let count = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| {
            crate::volume::dnode::put64(b, I_SIZE, new_size);
            Self::set_iblocks(b, count);
        })
    }
}
