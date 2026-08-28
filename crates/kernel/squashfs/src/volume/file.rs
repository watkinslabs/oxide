//! The block list, and reading a file's bytes.
//!
//! A file is a run of whole blocks, each independently compressed, followed by
//! an optional TAIL packed into a block shared with other files' tails. A
//! block's address is the sum of every preceding block's ON-DISK length, so a
//! single mis-decoded length word moves every block after it — the read still
//! succeeds and returns another file's bytes.
//!
//! A block whose on-disk length is zero is a HOLE: it occupies nothing and
//! reads as zeroes. Fetching it would read whatever the next block is.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::block::{data_length, BlockLen};
use crate::uapi::size;

use super::inode::{Fragment, Kind};
use super::meta::Cursor;
use super::{Inode, Volume};

impl<S: SectorSource> Volume<S> {
    /// How many whole blocks a file of `size` has, given whether its tail is
    /// packed into a fragment. # C: O(1)
    pub(super) fn whole_blocks(&self, size: u64, has_fragment: bool) -> u64 {
        let bs = u64::from(self.sb.block_size);
        if has_fragment { size / bs } else { size.div_ceil(bs) }
    }

    /// Read a file's list of block length words. # C: O(block count)
    pub(super) fn read_block_list(&self, cur: &mut Cursor, size: u64, has_fragment: bool)
        -> Result<Vec<u32>, Errno> {
        let n = usize::try_from(self.whole_blocks(size, has_fragment)).map_err(|_| Errno::Eio)?;
        let raw = self.read_meta(cur, n * size::BLOCK_LIST_ENTRY)?;
        Ok(raw.chunks_exact(size::BLOCK_LIST_ENTRY)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }

    /// Where block `index` of a file sits, and how long it is on the medium.
    ///
    /// The address is a running sum over the preceding blocks, so every length
    /// word before `index` is decoded — and a word that cannot be decoded stops
    /// the walk instead of contributing a wrong number to the sum.
    /// # C: O(index)
    pub fn block_location(&self, node: &Inode, index: u64) -> Result<(u64, BlockLen), Errno> {
        let Kind::Reg { start, blocks, .. } = &node.kind else { return Err(Errno::Eisdir) };
        let index = usize::try_from(index).map_err(|_| Errno::Eio)?;
        if index >= blocks.len() { return Err(Errno::Eio); }
        let mut at = *start;
        for word in &blocks[..index] {
            at = at.checked_add(data_length(*word)?.on_disk as u64).ok_or(Errno::Eio)?;
        }
        Ok((at, data_length(blocks[index])?))
    }

    /// The decompressed contents of one whole block of a file.
    ///
    /// `expected` is what the FILE says this block holds — the block size, or
    /// the remainder for a final block with no fragment. A sparse block is
    /// that many zero bytes and is never fetched.
    /// # C: O(block bytes)
    fn read_data_block(&self, node: &Inode, index: u64, expected: usize)
        -> Result<Arc<Vec<u8>>, Errno> {
        let (at, len) = self.block_location(node, index)?;
        if len.is_sparse() { return Ok(Arc::new(alloc::vec![0u8; expected])); }
        if let Some(hit) = self.data_cache_get(at) { return Ok(hit); }
        let mut raw = alloc::vec![0u8; len.on_disk];
        self.read_at(at, &mut raw)?;
        let out = if len.compressed {
            Arc::new(self.read_result(self.sb.codec.decompress_exact(&raw, expected))?)
        } else {
            if raw.len() != expected { return Err(Errno::Eio); }
            Arc::new(raw)
        };
        self.data_cache_put(at, &out);
        Ok(out)
    }

    /// The decompressed contents of a fragment block, whole.
    ///
    /// Bounded by the image's block size and not by the file's tail length: a
    /// fragment block holds several files' tails, and this file's begins part
    /// way in.
    /// # C: O(block bytes)
    pub fn read_fragment_block(&self, frag: &Fragment) -> Result<Arc<Vec<u8>>, Errno> {
        let len = self.read_result(data_length(frag.size_word))?;
        if len.is_sparse() { return Err(Errno::Eio); }
        if let Some(hit) = self.data_cache_get(frag.block) { return Ok(hit); }
        let mut raw = alloc::vec![0u8; len.on_disk];
        self.read_at(frag.block, &mut raw)?;
        let out = if len.compressed {
            Arc::new(self.read_result(
                self.sb.codec.decompress_bounded(&raw, self.sb.block_size as usize))?)
        } else {
            Arc::new(raw)
        };
        self.data_cache_put(frag.block, &out);
        Ok(out)
    }

    /// Read `buf.len()` bytes of a file starting at `off`, returning how many
    /// were produced. A read past the end produces none.
    /// # C: O(bytes read + blocks touched)
    pub fn read_file(&self, node: &Inode, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let Kind::Reg { fragment, .. } = &node.kind else { return Err(Errno::Eisdir) };
        if off >= node.size { return Ok(0); }
        let bs = u64::from(self.sb.block_size);
        let want = core::cmp::min(buf.len() as u64, node.size - off) as usize;
        let last = node.size / bs;
        let mut done = 0usize;
        while done < want {
            let at = off + done as u64;
            let index = at / bs;
            let within = usize::try_from(at % bs).map_err(|_| Errno::Eio)?;
            // The cached block, plus the window of it this file owns. A
            // fragment block holds several files' tails, so the window is not
            // the whole block; a data block's window is all of it.
            let (chunk, base, end) = if index == last && fragment.is_some() {
                let frag = fragment.as_ref().ok_or(Errno::Eio)?;
                let whole = self.read_fragment_block(frag)?;
                let tail = usize::try_from(node.size % bs).map_err(|_| Errno::Eio)?;
                let base = frag.offset as usize;
                let end = base.checked_add(tail).ok_or(Errno::Eio)?;
                if end > whole.len() { return Err(Errno::Eio); }
                (whole, base, end)
            } else {
                let expected = if index == last {
                    usize::try_from(node.size % bs).map_err(|_| Errno::Eio)?
                } else {
                    self.sb.block_size as usize
                };
                if expected == 0 { return Err(Errno::Eio); }
                let whole = self.read_data_block(node, index, expected)?;
                let end = whole.len();
                (whole, 0, end)
            };
            let window = &chunk[base..end];
            if within >= window.len() { return Err(Errno::Eio); }
            let take = core::cmp::min(want - done, window.len() - within);
            buf[done..done + take].copy_from_slice(&window[within..within + take]);
            done += take;
        }
        Ok(done)
    }

    /// A whole file's bytes. # C: O(file bytes)
    pub fn read_whole(&self, node: &Inode) -> Result<Vec<u8>, Errno> {
        let n = usize::try_from(node.size).map_err(|_| Errno::Eio)?;
        let mut out = alloc::vec![0u8; n];
        let got = self.read_file(node, 0, &mut out)?;
        out.truncate(got);
        Ok(out)
    }
}
