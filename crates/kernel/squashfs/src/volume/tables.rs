//! The index tables read at mount, and the lookups through them.
//!
//! Every index table is an array of 64-bit addresses of metadata blocks. Their
//! validity is stated BACKWARDS from the end of the image: each table's own
//! bytes must exactly fill the gap between where it starts and where the table
//! after it begins, and the blocks it addresses must sit below it, in order,
//! no further apart than one metadata block. Checking the chain in one pass at
//! mount is what makes a later lookup a plain index.

use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::uapi::{size, BLOCK_OFFSET, INVALID_BLK, METADATA_SIZE};

use super::meta::Cursor;
use super::{MountError, Volume};

/// Two addressed metadata blocks may not be further apart than one block plus
/// its length word.
const MAX_BLOCK_SPAN: u64 = METADATA_SIZE as u64 + BLOCK_OFFSET;

/// Decode a table of little-endian 64-bit addresses. # C: O(bytes)
fn addresses(bytes: &[u8]) -> Vec<u64> {
    bytes.chunks_exact(size::TABLE_INDEX)
        .map(|c| { let mut w = [0u8; 8]; w.copy_from_slice(c); u64::from_le_bytes(w) })
        .collect()
}

/// Every addressed block sits below `above`, in ascending order, within one
/// metadata block of its neighbour.
fn check_chain(table: &[u64], above: u64, what: &'static str) -> Result<(), MountError> {
    let last = *table.last().ok_or(MountError::Table(what))?;
    for pair in table.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if start >= end || end - start > MAX_BLOCK_SPAN { return Err(MountError::Table(what)); }
    }
    if last >= above || above - last > MAX_BLOCK_SPAN { return Err(MountError::Table(what)); }
    Ok(())
}

impl<S: SectorSource> Volume<S> {
    /// Read and bound every index table, walking back from the end of the image.
    /// # C: O(index table bytes)
    pub(super) fn read_index_tables(&mut self) -> Result<(), MountError> {
        let mut next = self.sb.bytes_used;
        if self.sb.xattr_id_table_start != INVALID_BLK { next = self.read_xattr_index()?; }
        next = self.read_id_index(next)?;
        if self.sb.lookup_table_start != INVALID_BLK { next = self.read_lookup_index(next)?; }
        if self.sb.fragments != 0 { next = self.read_fragment_index(next)?; }
        // The directory table is what the tables above sit after; an image
        // whose directory table starts past the first of them overlaps its own
        // metadata with its own index.
        if self.sb.directory_table_start > next { return Err(MountError::Table("directory_table")); }
        Ok(())
    }

    /// The xattr index, plus where the xattr stream itself begins.
    fn read_xattr_index(&mut self) -> Result<u64, MountError> {
        let head = self.sb.xattr_id_table_start;
        let raw = self.read_table(head, size::XATTR_ID_TABLE)?;
        let mut w = [0u8; 8];
        w.copy_from_slice(&raw[0..8]);
        let xattr_table = u64::from_le_bytes(w);
        let ids = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        if ids == 0 { return Err(MountError::Table("xattr_ids")); }
        let start = head + size::XATTR_ID_TABLE as u64;
        let len = index_bytes(u64::from(ids) * size::XATTR_ID as u64);
        if len != self.sb.bytes_used.checked_sub(start).ok_or(MountError::Table("xattr_index"))? {
            return Err(MountError::Table("xattr_index length"));
        }
        let table = addresses(&self.read_table(start, len as usize)?);
        check_chain(&table, head, "xattr_index")?;
        if xattr_table >= table[0] { return Err(MountError::Table("xattr_table above index")); }
        self.xattr_table = xattr_table;
        self.xattr_ids = ids;
        self.xattr_index = table;
        Ok(xattr_table)
    }

    fn read_id_index(&mut self, next: u64) -> Result<u64, MountError> {
        let head = self.sb.id_table_start;
        let len = self.sb.id_index_bytes();
        if len != next.checked_sub(head).ok_or(MountError::Table("id_index"))? {
            return Err(MountError::Table("id_index length"));
        }
        let table = addresses(&self.read_table(head, len as usize)?);
        check_chain(&table, head, "id_index")?;
        let first = table[0];
        self.id_index = table;
        Ok(first)
    }

    fn read_lookup_index(&mut self, next: u64) -> Result<u64, MountError> {
        let head = self.sb.lookup_table_start;
        if self.sb.inodes == 0 { return Err(MountError::Table("inodes")); }
        let len = self.sb.lookup_index_bytes();
        if len != next.checked_sub(head).ok_or(MountError::Table("lookup_index"))? {
            return Err(MountError::Table("lookup_index length"));
        }
        let table = addresses(&self.read_table(head, len as usize)?);
        check_chain(&table, head, "lookup_index")?;
        let first = table[0];
        self.lookup_index = table;
        Ok(first)
    }

    fn read_fragment_index(&mut self, next: u64) -> Result<u64, MountError> {
        let head = self.sb.fragment_table_start;
        let len = self.sb.fragment_index_bytes();
        let end = head.checked_add(len).ok_or(MountError::Table("fragment_index"))?;
        if end > next { return Err(MountError::Table("fragment_index length")); }
        let table = addresses(&self.read_table(head, len as usize)?);
        if table.is_empty() || table[0] >= head { return Err(MountError::Table("fragment_index")); }
        let first = table[0];
        self.fragment_index = table;
        Ok(first)
    }

    /// The real 32-bit identifier one uid/gid slot names.
    ///
    /// A stored inode holds an INDEX into this table, not an identifier, so an
    /// index the table does not cover is `EINVAL` and never a plausible id.
    /// # C: O(1) after mount
    pub fn id_of(&self, index: u16) -> Result<u32, Errno> {
        if u32::from(index) >= u32::from(self.sb.no_ids) { return Err(Errno::Einval); }
        let byte = usize::from(index) * size::ID_ENTRY;
        let mut cur = self.index_cursor(&self.id_index, byte)?;
        let raw = self.read_meta(&mut cur, size::ID_ENTRY)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    /// Where in the xattr index a given identifier's record lives.
    /// # C: O(1)
    pub(super) fn xattr_id_cursor(&self, id: u32) -> Result<Cursor, Errno> {
        if id >= self.xattr_ids { return Err(Errno::Einval); }
        let byte = id as usize * size::XATTR_ID;
        self.index_cursor(&self.xattr_index, byte)
    }

    /// Where in the fragment index a given byte offset lives. # C: O(1)
    pub(super) fn fragment_cursor(&self, byte: usize) -> Result<Cursor, Errno> {
        self.index_cursor(&self.fragment_index, byte)
    }

    /// Where the xattr key/value stream starts. # C: O(1)
    pub(super) fn xattr_table_start(&self) -> u64 { self.xattr_table }

    /// The cursor addressing byte `byte` of a metadata-chunked table.
    fn index_cursor(&self, table: &[u64], byte: usize) -> Result<Cursor, Errno> {
        let block = byte / METADATA_SIZE;
        let offset = byte % METADATA_SIZE;
        let start = *table.get(block).ok_or(Errno::Einval)?;
        Ok(Cursor::new(start, offset))
    }
}

/// Bytes an index covering `bytes` of a metadata-chunked table occupies.
fn index_bytes(bytes: u64) -> u64 {
    bytes.div_ceil(METADATA_SIZE as u64) * size::TABLE_INDEX as u64
}
