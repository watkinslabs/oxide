//! Reading a directory, and resolving one name in it.
//!
//! A listing is a run of HEADERS, each introducing up to a fixed number of
//! entries that share a metadata block and an inode-number base. Two things in
//! that encoding produce plausible wrong answers when read carelessly:
//!
//! - An entry's inode number is a SIGNED 16-bit delta from its header's base,
//!   so a name whose inode was allocated before the header's reads as a large
//!   positive number when taken unsigned.
//! - Neither `.` nor `..` is stored. They are emitted by the reader, which is
//!   why the position a caller sees is three ahead of the on-disk one.

use alloc::string::String;
use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::limits::{DIR_COUNT, NAME_LEN};
use crate::superblock::make_reference;
use crate::uapi::{size, MAX_DIR_TYPE, METADATA_SIZE};

use super::inode::{DirIndexLoc, Kind};
use super::meta::Cursor;
use super::{Inode, Volume};

/// The two names a listing does not store, which the reader supplies.
pub const SYNTHETIC_ENTRIES: u64 = 3;

/// One name in a directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub name: String,
    /// Reference of the named inode, ready for `read_inode`.
    pub reference: u64,
    pub ino: u32,
    /// The BASIC type discriminant; a listing never records an extended one.
    pub type_word: u16,
    /// The on-disk position just past this entry, offset by the synthetic
    /// entries so a caller's position and this agree.
    pub next_pos: u64,
}

/// One entry of a directory's name index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirIndex {
    pub index: u32,
    pub start_block: u32,
    pub name: Vec<u8>,
}

fn u16_at(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl<S: SectorSource> Volume<S> {
    /// Where a directory's listing begins, and how many bytes it spans.
    fn listing(&self, node: &Inode) -> Result<(Cursor, u64), Errno> {
        match &node.kind {
            Kind::Dir { start_block, offset, .. } => Ok((
                Cursor::new(self.sb.directory_table_start + u64::from(*start_block),
                            usize::from(*offset)),
                node.size,
            )),
            _ => Err(Errno::Enotdir),
        }
    }

    /// Every name in a directory, in stored order.
    /// # C: O(listing bytes)
    pub fn read_dir(&self, node: &Inode) -> Result<Vec<DirEntry>, Errno> {
        let (mut cur, size_bytes) = self.listing(node)?;
        let mut out = Vec::new();
        let mut length: u64 = 0;
        while length < size_bytes {
            let (base_ino, block, count) = self.read_dir_header(&mut cur, &mut length)?;
            for _ in 0..count {
                out.push(self.read_dir_entry(&mut cur, &mut length, base_ino, block)?);
            }
        }
        Ok(out)
    }

    /// Resolve one name.
    ///
    /// The listing is sorted, so a name that sorts before the entry under the
    /// cursor cannot appear later and the walk stops — which is what makes a
    /// miss cost half a directory instead of all of it. The index narrows the
    /// starting point; it is an optimisation and a damaged one only costs
    /// time, so a failure to read it falls back to the whole listing.
    /// # C: O(listing bytes) worst case, O(index + one metadata block) typical
    pub fn lookup(&self, node: &Inode, name: &str) -> Result<DirEntry, Errno> {
        if name.len() > NAME_LEN { return Err(Errno::Enametoolong); }
        let (start, size_bytes) = self.listing(node)?;
        let index = match &node.kind { Kind::Dir { index, .. } => *index, _ => None };
        let (mut cur, mut length) = self.index_by_name(start, index, name.as_bytes());
        while length < size_bytes {
            let (base_ino, block, count) = self.read_dir_header(&mut cur, &mut length)?;
            for _ in 0..count {
                let hit = self.read_dir_entry(&mut cur, &mut length, base_ino, block)?;
                if hit.name.as_bytes() > name.as_bytes() { return Err(Errno::Enoent); }
                if hit.name == name { return Ok(hit); }
            }
        }
        Err(Errno::Enoent)
    }

    /// A directory's name index, when it has one. # C: O(index bytes)
    pub fn read_dir_index(&self, node: &Inode) -> Result<Vec<DirIndex>, Errno> {
        let Kind::Dir { index: Some(loc), .. } = &node.kind else { return Ok(Vec::new()) };
        let mut cur = loc.cursor;
        let mut out = Vec::with_capacity(usize::from(loc.count));
        for _ in 0..loc.count {
            let b = self.read_meta(&mut cur, size::DIR_INDEX)?;
            let name_len = u32_at(&b, 8) as usize + 1;
            if name_len > NAME_LEN { return Err(Errno::Eio); }
            out.push(DirIndex {
                index: u32_at(&b, 0),
                start_block: u32_at(&b, 4),
                name: self.read_meta(&mut cur, name_len)?,
            });
        }
        Ok(out)
    }

    /// Advance the starting cursor past every index entry that sorts before
    /// `name`, and say how many listing bytes were skipped.
    fn index_by_name(&self, start: Cursor, loc: Option<DirIndexLoc>, name: &[u8])
        -> (Cursor, u64) {
        let Some(loc) = loc else { return (start, 0) };
        let mut cur = loc.cursor;
        let mut block = start.block;
        let mut length = 0u32;
        for _ in 0..loc.count {
            let Ok(b) = self.read_meta(&mut cur, size::DIR_INDEX) else { break };
            let name_len = u32_at(&b, 8) as usize + 1;
            if name_len > NAME_LEN { break; }
            let Ok(entry_name) = self.read_meta(&mut cur, name_len) else { break };
            // The stored name carries a trailing NUL that the comparison must
            // not see; comparing with it makes every index entry sort after a
            // name that is its prefix.
            let entry_name = trim_nul(&entry_name);
            if entry_name > name { break; }
            length = u32_at(&b, 0);
            block = self.sb.directory_table_start + u64::from(u32_at(&b, 4));
        }
        let offset = (length as usize + start.offset) % METADATA_SIZE;
        (Cursor::new(block, offset), u64::from(length))
    }

    /// Where in a listing a given caller position starts, and the on-disk
    /// position that corresponds to.
    ///
    /// A position at or below the synthetic entries is the start of the
    /// listing; past them, the index says which metadata block holds it.
    /// # C: O(index entries)
    pub(super) fn index_by_pos(&self, node: &Inode, pos: u64) -> Result<(Cursor, u64), Errno> {
        let (start, _) = self.listing(node)?;
        if pos <= SYNTHETIC_ENTRIES { return Ok((start, pos)); }
        let want = pos - SYNTHETIC_ENTRIES;
        let Kind::Dir { index: Some(loc), .. } = &node.kind else { return Ok((start, 0)) };
        let mut cur = loc.cursor;
        let mut block = start.block;
        let mut length = 0u32;
        for _ in 0..loc.count {
            let Ok(b) = self.read_meta(&mut cur, size::DIR_INDEX) else { break };
            if u64::from(u32_at(&b, 0)) > want { break; }
            let name_len = u32_at(&b, 8) as usize + 1;
            if name_len > NAME_LEN { break; }
            if self.skip_meta(&mut cur, name_len).is_err() { break; }
            length = u32_at(&b, 0);
            block = self.sb.directory_table_start + u64::from(u32_at(&b, 4));
        }
        let offset = (length as usize + start.offset) % METADATA_SIZE;
        Ok((Cursor::new(block, offset), u64::from(length)))
    }

    /// One header: the inode-number base, the metadata block its entries live
    /// in, and how many of them follow.
    fn read_dir_header(&self, cur: &mut Cursor, length: &mut u64)
        -> Result<(u32, u32, u32), Errno> {
        let b = self.read_meta(cur, size::DIR_HEADER)?;
        *length += size::DIR_HEADER as u64;
        let count = u32_at(&b, 0).checked_add(1).ok_or(Errno::Eio)?;
        if count > DIR_COUNT { return Err(Errno::Eio); }
        Ok((u32_at(&b, 8), u32_at(&b, 4), count))
    }

    /// One entry under a header.
    fn read_dir_entry(&self, cur: &mut Cursor, length: &mut u64, base_ino: u32, block: u32)
        -> Result<DirEntry, Errno> {
        let b = self.read_meta(cur, size::DIR_ENTRY)?;
        let name_len = usize::from(u16_at(&b, 6)) + 1;
        if name_len > NAME_LEN { return Err(Errno::Eio); }
        let raw = self.read_meta(cur, name_len)?;
        *length += (size::DIR_ENTRY + name_len) as u64;
        let type_word = u16_at(&b, 4);
        if type_word == 0 || type_word > MAX_DIR_TYPE { return Err(Errno::Eio); }
        let name = String::from_utf8(raw).map_err(|_| Errno::Eio)?;
        Ok(DirEntry {
            name,
            reference: make_reference(u64::from(block), u64::from(u16_at(&b, 0))),
            ino: apply_delta(base_ino, u16_at(&b, 2)),
            type_word,
            next_pos: *length + SYNTHETIC_ENTRIES,
        })
    }
}

/// Apply a header's signed inode-number delta.
///
/// The delta is signed: a name whose inode was allocated before its header's
/// base carries a negative one, and reading it unsigned yields a number some
/// sixty-five thousand too high — which still looks like an inode number.
/// # C: O(1)
pub fn apply_delta(base: u32, delta: u16) -> u32 {
    base.wrapping_add(i32::from(delta as i16) as u32)
}

/// Drop the trailing NUL a stored index name carries.
fn trim_nul(name: &[u8]) -> &[u8] {
    match name.iter().position(|b| *b == 0) { Some(n) => &name[..n], None => name }
}

#[cfg(test)]
#[path = "../tests/delta.rs"]
mod tests;
