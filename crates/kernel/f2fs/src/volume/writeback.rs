//! Putting a file's dirty data pages on the medium, and choosing where.
//!
//! A buffered write does not allocate. It takes the room and the owner's
//! quota, writes a RESERVATION into the file's node, and leaves the bytes in
//! the file mapping; the segment, the log and the block address are decided
//! HERE, once, for the whole batch a flush hands over. That is what makes the
//! filesystem's writes sequential — a thousand scattered one-byte writes
//! become one run through one log — and it is why the reference chooses an
//! address at writeback and nowhere else.
//!
//! Two things must NOT happen here and each has cost a defect elsewhere:
//!
//! - The room must not be asked for again. It was taken when the reservation
//!   was made, so a second demand at writeback refuses a write the caller was
//!   already told had succeeded, on exactly the full volume where it matters.
//! - The page must not be forgotten. Every other writer changes a block's
//!   address because its contents changed under a mapping that still holds the
//!   old ones; this writer is PUTTING the page it holds at the new address, so
//!   the two agree and dropping it would throw away the only copy of a write
//!   and make the next read fetch bytes it already had.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use block::pagecache::PageOut;
use block::types::{BlockError, KResult};

use crate::filemap::Cache;
use crate::uapi::{BLKSIZE, NEW_ADDR};

use super::curseg::Kind;
use super::dnode::Holder;
use super::fileops::{mode_ifdir, mode_ifmt};
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Put a batch of one file's pages on the medium, one address per page.
    ///
    /// One slot of `results` per page, arriving prefilled with a failure: a
    /// page this leaves unreported is re-dirtied by the layer below rather
    /// than dropped, which is the only safe reading of "the target did not say".
    /// # Ctx: process # Sleeps: y # C: O(pages) blocks
    pub(crate) fn writeback_data_pages(&mut self, ino: u32, pages: &[PageOut<'_>],
                                       results: &mut [KResult<()>], first: &mut Option<Errno>) {
        // A compressed file's pages are not placed one at a time and cannot be:
        // the cluster they belong to is one image, so its bytes, its shape and
        // its addresses are all decided together, once, for the whole cluster.
        if self.read_inode(ino).map(|i| i.compressed()).unwrap_or(false) {
            return self.writeback_compressed_pages(ino, pages, results, first);
        }
        for (i, p) in pages.iter().enumerate() {
            let index = Cache::index_of(p);
            results[i] = match self.writeback_one(ino, index, p.data) {
                Ok(()) => Ok(()),
                Err(e) => { if first.is_none() { *first = Some(e); } Err(BlockError::Eio) }
            };
        }
    }

    /// One page: where it goes, the bytes that land, and the slot that names
    /// it afterwards. # C: O(indirection depth) blocks
    fn writeback_one(&mut self, ino: u32, index: u64, data: &[u8]) -> Result<(), Errno> {
        self.writable_or_err()?;
        if data.len() != BLKSIZE { return Err(Errno::Einval); }
        let inode = self.read_inode(ino)?;
        // The mapping holds PLAINTEXT, so the cipher is put back on HERE, on
        // the way out. Doing it when the page was dirtied would leave the
        // mapping holding ciphertext, and every read of that offset would hand
        // the caller noise.
        let crypt = self.crypt_info(&inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        // The node already exists — the reservation is in it — but the walk is
        // the same one, and asking for it rather than remembering it is what
        // keeps this correct after a cleaner has moved the nodes underneath.
        let (holder, ofs) = self.dnode_for_write(ino, index)?;
        let old = self.holder_addr(ino, holder, ofs)?;
        let mut page = data.to_vec();
        if let Some(c) = &crypt {
            if !c.uses_inline_crypto() {
                c.crypt_contents(self.first_unit(c, index), &mut page, true)
                    .map_err(|e| e.errno())?;
            }
        }
        let ctx = self.write_ctx(crypt.as_ref(), index);
        let is_dir = inode.mode & mode_ifmt() == mode_ifdir();
        let owner = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
        let flags = self.data_write_flags(ino);
        // Back onto the block it came from, where the volume's state allows it
        // (`placement`). Nothing else changes: the segment table already counts
        // the block, the summary already names this owner and offset, and the
        // slot already holds this address — so the node above the page is not
        // rewritten, which is the whole saving. Before the allocation, because
        // an allocation is the thing being avoided.
        if self.writes_in_place(ino, &inode, old, self.sync_writeback)? {
            self.write_data_in_place(old, &page, flags, ctx.as_ref())?;
            // The file now has bytes on a block nothing about its recorded
            // shape distinguishes from the one the checkpoint already holds, so
            // no later comparison can tell that anything happened. Recorded
            // HERE, at the one site that both performed the rewrite and knows
            // whose file it was, because the only thing that can still make
            // those bytes durable is a barrier, and `fsync` has no other way to
            // learn that one is owed.
            self.note_inplace_write(ino);
            return Ok(());
        }
        let kind = if is_dir { Kind::DirData } else { Kind::FileData };
        let addr = self.write_data_crypt(ino, kind, owner, ofs as u16, old, &page, flags, ctx.as_ref())?;
        self.set_holder_addr_keeping_page(ino, holder, ofs, addr)?;
        // The room the reservation was holding is the room this block just
        // took. Released after the slot names a real block, so a failure above
        // leaves the reservation intact and the page still dirty.
        if old == NEW_ADDR { self.release_reservation(); }
        Ok(())
    }

    /// Write back every dirty page of `ino`, reporting the first failure.
    ///
    /// The mount's own flush path: the sink goes straight to the volume rather
    /// than through the mapping's installed target, which exists for callers
    /// arriving from outside this filesystem holding none of its state.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages of this inode)
    pub(crate) fn flush_data_pages(&mut self, ino: u32) -> Result<(), Errno> {
        let cache = Arc::clone(&self.data_cache);
        let mut first: Option<Errno> = None;
        // Somebody is waiting on this one, which is what parts it from the
        // flusher's batches and what one placement policy asks about. Restored
        // afterwards rather than cleared, so a flush inside a flush leaves the
        // outer one's answer alone.
        let waited = core::mem::replace(&mut self.sync_writeback, true);
        let (_, out) = cache.flush(ino, usize::MAX, &mut |_ino, pages, results| {
            self.writeback_data_pages(ino, pages, results, &mut first);
        });
        self.sync_writeback = waited;
        match (first, out) {
            (Some(e), _) => Err(e),
            (None, Err(_)) => Err(Errno::Eio),
            (None, Ok(())) => Ok(()),
        }
    }

    /// The same, restricted to the INCLUSIVE page-index range `[lo, hi]`.
    ///
    /// What a range `fsync` and `sync_file_range(2)` ask for. The unbounded form
    /// is a correct superset and loses nothing, but a one-page flush of a large
    /// file has no business rewriting every unplaced page of it — the reference
    /// honours the range its writeback control carries.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages in range)
    pub(crate) fn flush_data_pages_range(&mut self, ino: u32, lo: u64, hi: u64)
        -> Result<(), Errno> {
        let cache = Arc::clone(&self.data_cache);
        let mut first: Option<Errno> = None;
        let waited = core::mem::replace(&mut self.sync_writeback, true);
        let (_, out) = cache.flush_range(ino, lo, hi, usize::MAX, &mut |_ino, pages, results| {
            self.writeback_data_pages(ino, pages, results, &mut first);
        });
        self.sync_writeback = waited;
        match (first, out) {
            (Some(e), _) => Err(e),
            (None, Err(_)) => Err(Errno::Eio),
            (None, Ok(())) => Ok(()),
        }
    }

    /// The same for every file this mount holds a dirty page of — what a
    /// checkpoint and an unmount owe the volume.
    ///
    /// The list is sampled once and then walked: writing a page dirties nodes,
    /// never other files' data, so a file that appears while this runs did so
    /// after the flush began and belongs to the next one.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages)
    pub(crate) fn flush_all_data_pages(&mut self) -> Result<(), Errno> {
        let inos: Vec<u32> = self.data_cache.dirty_inodes();
        let mut first: Option<Errno> = None;
        for ino in inos {
            if let Err(e) = self.flush_data_pages(ino) { if first.is_none() { first = Some(e); } }
        }
        match first { Some(e) => Err(e), None => Ok(()) }
    }

    /// Place every pending write this mount holds, without a checkpoint.
    ///
    /// What a caller that is about to READ ADDRESSES rather than bytes needs:
    /// a page not yet placed has none, so a question about where a file's
    /// blocks are has no answer until they exist. The flush points inside this
    /// filesystem call it for their own inode; this is the whole-mount form.
    ///
    /// NODES as well as data, and in that order: a node holds the addresses of
    /// the blocks under it and is itself placed late, so a caller that wanted
    /// addresses and got only the data flush would read a node table naming
    /// nodes that are not on the medium. Placing a data page changes the node
    /// above it, which is why the data half goes first.
    /// # Ctx: process # Sleeps: y # C: O(dirty pages)
    pub fn sync_data(&mut self) -> Result<(), Errno> {
        self.flush_all_data_pages()?;
        self.flush_all_nodes()
    }

    /// The mapping this mount reads and writes its files' data through.
    ///
    /// Handed out so the filesystem above can give it the way back to itself:
    /// the machine's flusher and reclaim reach these pages holding none of
    /// this mount's state, and need somewhere to send them.
    /// # C: O(1)
    pub fn data_cache(&self) -> Arc<crate::filemap::Cache> { Arc::clone(&self.data_cache) }

    /// Pages of `ino` written but not yet placed. # C: O(1)
    pub fn dirty_data_pages(&self, ino: u32) -> usize { self.data_cache.dirty_pages(ino) }
}

#[cfg(test)]
#[path = "../tests/pagewrite.rs"]
mod tests;
