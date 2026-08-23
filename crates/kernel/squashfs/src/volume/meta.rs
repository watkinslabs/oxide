//! Reading bytes, metadata blocks, and the metadata BYTE STREAM.
//!
//! A structure on this filesystem is not a slice of one block. Metadata blocks
//! decompress to at most a fixed size, and the build tool packs structures
//! across their boundaries, so a directory header can begin in one block and
//! end in the next. Every read of a structure is therefore a loop over a
//! `(block, offset)` cursor, and the cursor is what the caller keeps — reading
//! a structure ADVANCES it to whatever follows.

use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::block::metadata_length;
use crate::limits::MAX_META_BLOCKS;
use crate::uapi::{BLOCK_OFFSET, METADATA_SIZE};

use super::Volume;

/// A position in the metadata byte stream.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cursor {
    /// Byte address of the metadata block's LENGTH WORD on the medium.
    pub block: u64,
    /// Byte offset within that block once decompressed.
    pub offset: usize,
}

impl Cursor {
    /// # C: O(1)
    pub fn new(block: u64, offset: usize) -> Self { Self { block, offset } }
}

/// One decompressed metadata block and where the next one starts.
pub struct MetaBlock {
    pub data: Vec<u8>,
    pub next: u64,
}

impl<S: SectorSource> Volume<S> {
    /// Raw bytes at a byte address, bounded by what the image claims to be.
    ///
    /// The bound is against `bytes_used` and not against the medium: an image
    /// smaller than its medium must not be able to read whatever follows it,
    /// and the superblock check already refused the reverse case.
    /// # C: O(len)
    pub(crate) fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let end = off.checked_add(buf.len() as u64).ok_or(Errno::Eio)?;
        if end > self.sb.bytes_used { return Err(Errno::Eio); }
        self.read_result(self.src.read_sectors(off, buf))
    }

    /// A whole uncompressed TABLE, read straight off the medium.
    ///
    /// The index tables are written uncompressed by construction, so this is a
    /// byte read and not a metadata-block read; treating one as the other
    /// consumes the first two bytes as a length word.
    /// # C: O(len)
    pub(crate) fn read_table(&self, start: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let mut out = alloc::vec![0u8; len];
        self.read_at(start, &mut out)?;
        Ok(out)
    }

    /// Decompress one metadata block, and say where the next one begins.
    /// # C: O(metadata block bytes)
    pub(crate) fn read_meta_block(&self, block: u64) -> Result<MetaBlock, Errno> {
        if let Some(hit) = self.meta_cache_get(block) { return Ok(hit); }
        let mut word = [0u8; BLOCK_OFFSET as usize];
        self.read_at(block, &mut word)?;
        let len = metadata_length(u16::from_le_bytes(word));
        if len.on_disk == 0 || len.on_disk > METADATA_SIZE { return Err(Errno::Eio); }
        let body = block.checked_add(BLOCK_OFFSET).ok_or(Errno::Eio)?;
        let mut raw = alloc::vec![0u8; len.on_disk];
        self.read_at(body, &mut raw)?;
        let next = body.checked_add(len.on_disk as u64).ok_or(Errno::Eio)?;
        let data = if len.compressed {
            self.read_result(self.sb.codec.decompress_bounded(&raw, METADATA_SIZE))?
        } else {
            raw
        };
        if data.is_empty() || data.len() > METADATA_SIZE { return Err(Errno::Eio); }
        self.meta_cache_put(block, &data, next);
        Ok(MetaBlock { data, next })
    }

    /// Read `len` bytes of the metadata stream, advancing `cur` past them.
    ///
    /// A read that ends exactly on a block boundary steps the cursor to the
    /// next block, so the following read starts where the build tool put it —
    /// leaving the cursor at `offset == block length` instead would make the
    /// next read reject a perfectly good stream.
    /// # C: O(len + blocks crossed)
    pub(crate) fn read_meta(&self, cur: &mut Cursor, len: usize) -> Result<Vec<u8>, Errno> {
        if len > MAX_META_BLOCKS * METADATA_SIZE { return Err(Errno::Eio); }
        let mut out = Vec::with_capacity(len);
        self.skip_or_take(cur, len, Some(&mut out))?;
        Ok(out)
    }

    /// Advance `cur` past `len` bytes without keeping them. # C: O(blocks crossed)
    pub(crate) fn skip_meta(&self, cur: &mut Cursor, len: usize) -> Result<(), Errno> {
        self.skip_or_take(cur, len, None)
    }

    fn skip_or_take(&self, cur: &mut Cursor, len: usize, mut out: Option<&mut Vec<u8>>)
        -> Result<(), Errno> {
        if cur.offset >= METADATA_SIZE { return Err(Errno::Eio); }
        let mut left = len;
        let mut crossed = 0usize;
        while left > 0 {
            crossed += 1;
            if crossed > MAX_META_BLOCKS { return Err(Errno::Eio); }
            let blk = self.read_meta_block(cur.block)?;
            if cur.offset >= blk.data.len() { return Err(Errno::Eio); }
            let take = core::cmp::min(left, blk.data.len() - cur.offset);
            if let Some(o) = out.as_deref_mut() {
                o.extend_from_slice(&blk.data[cur.offset..cur.offset + take]);
            }
            cur.offset += take;
            left -= take;
            if cur.offset == blk.data.len() { cur.block = blk.next; cur.offset = 0; }
        }
        Ok(())
    }
}
