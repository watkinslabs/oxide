//! `ZERO_RANGE`: the range reads as zeroes and DOES cost blocks.
//!
//! The mirror image of punching. Both leave the range reading as zeroes; this
//! one guarantees that writing into it afterwards cannot fail for want of
//! space, which is why it allocates instead of freeing. A caller uses it to
//! reserve a region it is about to fill.
//!
//! The partial blocks at each end are handled exactly as a punch handles them,
//! and the whole blocks between are given addresses. A block that already had
//! one is replaced rather than rewritten: the old block's contents are not
//! zeroes, and leaving it in place with the address unchanged would leave the
//! range reading as whatever was there.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::dnode::put64;
use crate::volume::Volume;

use super::uapi::FALLOC_FL_KEEP_SIZE;

impl<S: SectorSource> Volume<S> {
    /// Make `[offset, offset + len)` of `ino` read as zeroes, with blocks
    /// behind it. # C: O(blocks the range covers)
    pub(crate) fn zero_range(&mut self, ino: u32, offset: u64, len: u64, mode: u32)
        -> Result<(), Errno> {
        let end = offset + len;
        self.newsize_ok(ino, end)?;
        self.convert_inline(ino)?;
        let blk = BLKSIZE as u64;
        let mut new_size = self.read_inode(ino)?.size;
        let mut first = offset / blk;
        let last = end / blk;
        let head = (offset % blk) as usize;
        let tail = (end % blk) as usize;
        if first == last {
            self.fill_zero(ino, first, head, tail - head)?;
            new_size = new_size.max(end);
        } else {
            if head != 0 {
                self.fill_zero(ino, first, head, BLKSIZE - head)?;
                first += 1;
                new_size = new_size.max(first * blk);
            }
            for index in first..last {
                self.zero_one_block(ino, index)?;
                new_size = new_size.max((index + 1) * blk);
            }
            if tail != 0 {
                self.fill_zero(ino, last, 0, tail)?;
                new_size = new_size.max(end);
            }
        }
        let blocks = self.count_blocks(ino)?;
        // `KEEP_SIZE` is what parts this from an ordinary write: the blocks
        // exist and the file still says it is as short as it was, so reading
        // past the end reads nothing and a later truncate up exposes zeroes
        // rather than allocating.
        let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
        let size = if keep { self.read_inode(ino)?.size } else { new_size };
        self.stamp_inode(ino, |b| {
            put64(b, I_SIZE, size);
            Self::set_iblocks(b, blocks);
        })
    }

    /// Give one whole block of the range a block of zeroes.
    ///
    /// A block that already held data is REPLACED. Leaving its address alone
    /// would leave the range reading as whatever was there, which is the one
    /// thing this call promises it does not.
    /// # C: O(BLKSIZE)
    fn zero_one_block(&mut self, ino: u32, index: u64) -> Result<(), Errno> {
        let zeroes = alloc::vec![0u8; BLKSIZE];
        self.write_one_block(ino, index, 0, &zeroes)
    }
}
