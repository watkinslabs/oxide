//! What a SHARED MAPPING's write fault asks the volume for, before the write
//! is allowed to land.
//!
//! A store through a mapped page is a CPU write with no syscall behind it. The
//! filesystem sees exactly one event for it — this one — and everything a
//! buffered write decides on the way in has to be decided here or not at all:
//!
//! | decision | what happens if it is not made here |
//! |---|---|
//! | the file may be written | a store corrupts a file the filesystem refuses to change through every other route |
//! | the block is reserved | a hole has nowhere to be placed, so the write is lost at the flush that was told it succeeded — and `ENOSPC` and quota, which are refusals, arrive after the caller cannot be told |
//! | the page is resident and holds the file's bytes | the mapper writes part of a block whose other bytes were never read, and the flush puts zeroes over them |
//! | the tail past the end of the file is zero | the bytes past `i_size` in the last page reach the medium holding whatever the frame held before |
//! | the page is DIRTY | nothing else will ever mark it, so no flush, no `msync` and no checkpoint writes it |
//! | the mapped counters are charged | the one figure that says how much of a volume's traffic is mapped writes stays at zero however many there are |
//!
//! The ORDER is the reference's and is not free to change. The refusals come
//! first, while nothing has been changed. The reservation comes before the page
//! is filed, because reserving a slot is a mapping change and the notification
//! it fires drops the offset's page — reserving after filing would file the
//! bytes and then throw them away. The dirty mark comes last, because a page
//! marked dirty with no address reserved for it is a page the flusher cannot
//! place.
//!
//! What is NOT here: growing the file. A fault past the end of a mapping's
//! object is not a write the object accepts — the reference answers it as a bus
//! error rather than extending the file — so this refuses an index past the
//! last page of the file instead of reserving for it.

use sectors::SectorSource;

use syscall::errno::Errno;

use crate::stats::iostat::Io;
use crate::uapi::BLKSIZE;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// A shared mapping is about to write block `index` of `ino`.
    ///
    /// Reserves the block, brings the page in, zeroes any tail past the end of
    /// the file, and leaves the page DIRTY with the mapped write charged. The
    /// caller balances the machine's dirty state afterwards, with this volume's
    /// lock dropped.
    /// # Ctx: process # Sleeps: y # C: O(indirection depth) blocks
    pub(crate) fn mkwrite_page(&mut self, ino: u32, index: u64) -> Result<(), Errno> {
        self.writable_or_err()?;
        // The records the block this fault reserves is charged against are
        // brought in HERE, once, before anything is claimed — the same order the
        // buffered writer uses, and for the same reason: every promise below
        // then operates on memory and cannot fail part way for want of a read.
        self.dquot_initialize(ino)?;
        let inode = self.read_inode(ino)?;
        // A file whose contents are fixed is fixed however it is reached. A
        // mapping is not a way around the flag.
        if inode.flags & crate::flags::F2FS_IMMUTABLE_FL != 0 { return Err(Errno::Eperm); }
        // Sealed behind a hash tree: its contents are what the tree attests to.
        crate::verity::access::open_write(inode.flags).map_err(crate::verity::access::errno)?;
        // The bytes that reach the medium are ciphertext and there is no
        // plaintext form of a block on an encrypted volume, so a mapping of one
        // needs the key exactly as a write does.
        let crypt = self.crypt_info(&inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        // A compressed file's unpacked cluster is not held in this mapping at
        // all — the cluster reader unpacks per access — so there is no page here
        // for a user page table to point at and no place a store could land.
        // Refused rather than accepted-and-dropped: a store that appeared to
        // work and vanished at the flush is the failure this whole path exists
        // to remove.
        if inode.compressed() { return Err(Errno::Eopnotsupp); }
        // A span holds its writes in a shadow inode, so this inode's blocks are
        // not where a store through it belongs.
        if self.is_atomic_file(ino) { return Err(Errno::Eopnotsupp); }
        // The checkpoint recorded a failure: nothing more may be promised
        // against this volume.
        if self.checkpoint().has(crate::flags::CP_ERROR_FLAG) { return Err(Errno::Eio); }
        // A fault past the end of the file is not a write the file accepts.
        // Measured against the size NOW, which a write through any descriptor
        // may have moved since the mapping was made.
        let first_byte = index.checked_mul(BLKSIZE as u64).ok_or(Errno::Efbig)?;
        if first_byte >= inode.size { return Err(Errno::Einval); }
        // Data inside the inode block has no data block to reserve, and a
        // mapping cannot point at part of the inode. Moved out first, exactly
        // as the reference converts before it takes the block.
        if inode.inline_data() { self.convert_inline(ino)?; }

        let (holder, ofs) = self.dnode_for_write(ino, index)?;
        let old = self.holder_addr(ino, holder, ofs)?;
        // The page's bytes ARE the file's contents at this offset and may be
        // the only copy of them; read them before the slot changes under them.
        let page = self.mkwrite_page_bytes(ino, index, old)?;
        // Only a slot holding NOTHING is a claim on the volume's space. The
        // reservation keeps the mapping's page, because the page it reserves for
        // is the page the fault is about to hand to a user page table.
        if old == crate::uapi::NULL_ADDR {
            self.reserve_data_slot_keeping_page(ino, holder, ofs)?;
            // The file is charged for the block the moment the block belongs to
            // it. A reservation counts as a block the file holds — that is what
            // makes the count right before the address is chosen — and a count
            // left behind would have the file disagree with its own contents
            // until something else happened to recompute it.
            let blocks = self.count_blocks(ino)?;
            self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))?;
        }
        self.data_cache.write(ino, index, page)?;
        self.io_account(Io::AppMapped, BLKSIZE as u64, false);
        Ok(())
    }

    /// The whole block the fault will write into, with any tail past the end of
    /// the file zeroed.
    ///
    /// The tail matters because the page is written back whole: the bytes past
    /// `i_size` in the last page are not part of the file, and a flush that put
    /// the frame's previous contents there would publish them.
    /// # C: O(BLKSIZE)
    fn mkwrite_page_bytes(&mut self, ino: u32, index: u64, old: u32)
        -> Result<alloc::vec::Vec<u8>, Errno> {
        let inode = self.read_inode(ino)?;
        let crypt = self.crypt_info(&inode, ino)?;
        let mut page = match self.data_cache.peek(ino, index) {
            Some(held) => held,
            None if crate::node::is_hole(old) => alloc::vec![0u8; BLKSIZE],
            None => self.read_data_page_unattested(ino, index, old, crypt.as_ref())?,
        };
        if page.len() != BLKSIZE { return Err(Errno::Eio); }
        let first_byte = index.wrapping_mul(BLKSIZE as u64);
        let tail = inode.size.saturating_sub(first_byte);
        if tail < BLKSIZE as u64 { page[tail as usize..].fill(0); }
        Ok(page)
    }

    /// The machine frame page `index` of `ino` lives in, for a mapping to point
    /// at.
    ///
    /// The page has to be HELD first, which is what the fill below is for: a
    /// read fault of a shared mapping arrives with nothing resident, and a frame
    /// for a page the mapping does not hold would be a second copy of the file
    /// rather than the file.
    ///
    /// A HOLE gets a page too, and must. The read path files nothing for a hole
    /// — there is no block to have read — but a mapper still needs a page to
    /// point at, and it has to be THE page every later reader of that offset
    /// gets or the mapping and the file part company at the first store. Filed
    /// CLEAN: nothing has been written, and a dirty page here would have the
    /// next flush place a block for a hole nobody wrote.
    ///
    /// `None` means this file's pages cannot be mapped — a compressed file, or a
    /// frame that could not be had. Never a heap buffer offered as if a page
    /// table could point at it.
    /// # Ctx: process # Sleeps: y # C: O(1 block read) on a miss
    pub(crate) fn mapped_frame(&self, ino: u32, index: u64) -> Option<u64> {
        if !self.data_cache.holds(ino, index) {
            self.populate_mapped(ino, index, 1);
            if !self.data_cache.holds(ino, index) {
                let inode = self.read_inode(ino).ok()?;
                if inode.compressed() { return None; }
                let off = index.checked_mul(BLKSIZE as u64)?;
                if off >= inode.size { return None; }
                self.data_cache.insert_clean(ino, index, alloc::vec![0u8; BLKSIZE]);
                if !self.data_cache.holds(ino, index) { return None; }
            }
        }
        self.data_cache.map_frame(ino, index)
    }
}

#[cfg(test)]
#[path = "../tests/mkwrite.rs"]
mod tests;
