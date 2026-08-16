//! Adding and removing directory entries.
//!
//! A name needs a RUN of consecutive free slots, not one: its bytes span as
//! many eight-byte slots as it takes, and only the first carries a record. The
//! continuation slots' records are explicitly zeroed on insert — the format
//! leaves whatever a deleted entry put there, and a reader that walks slot by
//! slot would report it as an entry.
//!
//! Where an entry goes is decided by its hash, level by level. Level zero is
//! tried first; if no bucket block there has a run long enough, the directory
//! grows a level and the search repeats. A writer that only ever used level
//! zero would fill one bucket and report a full directory with the volume
//! nearly empty.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::dirent::{block as deblock, bucket, layout::is_used, Layout};
use crate::flags::*;
use crate::hash;
use crate::limits::MAX_LOOKUP_DEPTH;
use crate::uapi::*;

use super::dnode::{put16, put32};
use super::map::Mapped;
use super::Volume;

/// The first slot of a run of `slots` free slots, or `None`. # C: O(max slots)
pub fn room_for(area: &[u8], l: &Layout, slots: usize) -> Option<usize> {
    let mut start = 0usize;
    while start + slots <= l.max {
        match (start..start + slots).find(|&i| is_used(area, i)) {
            None => return Some(start),
            Some(hit) => start = hit + 1,
        }
    }
    None
}

/// Lay one entry into `area` at `slot`. # C: O(name len)
pub fn place_entry(area: &mut [u8], l: &Layout, slot: usize, name: &[u8], ino: u32, ft: u8) {
    place_entry_hashed(area, l, slot, name, hash::name_hash(name), ino, ft)
}

/// The same, under a hash the caller computed.
///
/// A folding directory stores the hash of the FOLDED name, so the bucket a
/// later lookup searches is the one every spelling of the name lands in.
/// Storing the raw hash there makes the entry findable only by the exact
/// spelling it was created with.
/// # C: O(name len)
#[allow(clippy::too_many_arguments)]
pub fn place_entry_hashed(area: &mut [u8], l: &Layout, slot: usize, name: &[u8], hash: u32,
                          ino: u32, ft: u8) {
    let slots = dentry_slots(name.len());
    let at = l.dentry_off(slot);
    put32(area, at + DE_HASH_CODE, hash);
    put32(area, at + DE_INO, ino);
    put16(area, at + DE_NAME_LEN, name.len() as u16);
    area[at + DE_FILE_TYPE] = ft;
    let name_at = l.name_off(slot);
    area[name_at..name_at + name.len()].copy_from_slice(name);
    for i in 0..slots {
        area[(slot + i) / 8] |= 1 << ((slot + i) % 8);
        // Every slot past the first is a continuation. Its record must read as
        // empty or a slot-by-slot walker reports a name nobody created.
        if i > 0 {
            let cont = l.dentry_off(slot + i);
            area[cont..cont + SIZE_OF_DIR_ENTRY].fill(0);
        }
    }
}

/// Clear the entry starting at `slot`, and every slot it spans.
///
/// Only the BITMAP is cleared. The record itself is left exactly as it was,
/// which is what the format does — and it is why an insert must zero the
/// continuation slots it covers: the bytes a deleted entry leaves behind are
/// still there, and a walker that steps one slot at a time reads them as an
/// entry that no longer exists.
/// # C: O(slots)
pub fn clear_entry(area: &mut [u8], l: &Layout, slot: usize) -> Option<u32> {
    let at = l.dentry_off(slot);
    let name_len = le16(area, at + DE_NAME_LEN)? as usize;
    let ino = le32(area, at + DE_INO)?;
    let slots = dentry_slots(name_len).max(1);
    for i in 0..slots {
        let s = slot + i;
        if s >= l.max { break; }
        area[s / 8] &= !(1 << (s % 8));
    }
    Some(ino)
}

/// Whether any slot of the area is in use. # C: O(bitmap bytes)
pub fn area_is_empty(area: &[u8], l: &Layout) -> bool {
    (0..l.max).all(|i| !is_used(area, i))
}

impl<S: SectorSource> Volume<S> {
    /// Add `name` to the directory `dir`, pointing at `ino`.
    /// # C: O(depth) blocks
    pub(crate) fn add_dentry(&mut self, dir: u32, name: &[u8], ino: u32, ft: u8)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        if name.is_empty() || name.len() > NAME_LEN { return Err(Errno::Enametoolong); }
        let inode = self.read_inode(dir)?;
        if inode.encrypted() { return Err(Errno::Eopnotsupp); }
        let want = self.entry_hash(&inode, name)?;
        let slots = dentry_slots(name.len());
        if inode.inline_dentry() {
            let (at, len) = inode.inline_data_span();
            let l = Layout::inline(len);
            let mut block = self.inode_bytes(dir)?;
            if let Some(slot) = room_for(&block[at..at + len], &l, slots) {
                place_entry_hashed(&mut block[at..at + len], &l, slot, name, want, ino, ft);
                self.put_inode(dir, block)?;
                return Ok(());
            }
            self.convert_inline_dir(dir)?;
        }
        self.add_regular_dentry(dir, name, ino, ft, slots, want)
    }

    /// Add to a directory whose entries live in blocks. # C: O(depth) blocks
    #[allow(clippy::too_many_arguments)]
    fn add_regular_dentry(&mut self, dir: u32, name: &[u8], ino: u32, ft: u8, slots: usize,
                          want: u32) -> Result<(), Errno> {
        let l = Layout::block();
        let inode = self.read_inode(dir)?;
        let dir_level = inode.dir_level;
        let mut depth = inode.current_depth.max(1);
        for level in 0..MAX_LOOKUP_DEPTH {
            for index in bucket::search_range(want, level, dir_level) {
                let mut area = match self.map_block(&inode, dir, index)? {
                    Mapped::At(addr) => self.read_main_block(addr)?,
                    Mapped::Compressed => return Err(Errno::Eio),
                    Mapped::Hole => vec![0u8; BLKSIZE],
                };
                let Some(slot) = room_for(&area, &l, slots) else { continue };
                place_entry_hashed(&mut area, &l, slot, name, want, ino, ft);
                self.write_one_block(dir, index, 0, &area)?;
                let size = ((index + 1) * BLKSIZE as u64).max(self.read_inode(dir)?.size);
                if level + 1 > depth { depth = level + 1; }
                let blocks = self.count_blocks(dir)?;
                return self.stamp_inode(dir, |b| {
                    super::dnode::put64(b, I_SIZE, size);
                    put32(b, I_CURRENT_DEPTH, depth);
                    Self::set_iblocks(b, blocks);
                });
            }
        }
        Err(Errno::Enospc)
    }

    /// Move an inline directory's entries out into block zero.
    ///
    /// The entries are re-laid under the BLOCK layout, which has different
    /// region sizes; copying the bytes across unchanged would put every record
    /// four bytes out.
    /// # C: O(entries)
    pub(crate) fn convert_inline_dir(&mut self, dir: u32) -> Result<(), Errno> {
        let inode = self.read_inode(dir)?;
        if !inode.inline_dentry() { return Ok(()); }
        let (at, len) = inode.inline_data_span();
        let block = self.inode_bytes(dir)?;
        let old = Layout::inline(len);
        let entries = deblock::entries(&block[at..at + len], &old).map_err(|_| Errno::Eio)?;
        let l = Layout::block();
        let mut area = vec![0u8; BLKSIZE];
        let mut slot = 0usize;
        for e in entries {
            let need = dentry_slots(e.name.len());
            if slot + need > l.max { return Err(Errno::Enospc); }
            place_entry(&mut area, &l, slot, &e.name, e.ino, e.file_type);
            slot += need;
        }
        // The flags come off first: the inline region and the address array
        // are the same bytes, so the entries must stop being reachable as
        // entries before the region is used as addresses.
        self.stamp_inode(dir, |b| {
            b[I_INLINE] &= !(INLINE_DENTRY | INLINE_DATA | DATA_EXIST);
            let base = OFFSET_OF_END_OF_I_EXT + le16(b, I_EXTRA_ISIZE).unwrap_or(0) as usize;
            b[base..base + len].fill(0);
            super::dnode::put64(b, I_SIZE, 0);
            put32(b, I_CURRENT_DEPTH, 1);
        })?;
        self.write_one_block(dir, 0, 0, &area)?;
        let blocks = self.count_blocks(dir)?;
        self.stamp_inode(dir, |b| {
            super::dnode::put64(b, I_SIZE, BLKSIZE as u64);
            Self::set_iblocks(b, blocks);
        })
    }

    /// Remove `name` from `dir`. Reports the inode it named. # C: O(depth)
    pub(crate) fn remove_dentry(&mut self, dir: u32, name: &[u8]) -> Result<u32, Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(dir)?;
        if inode.encrypted() { return Err(Errno::Eopnotsupp); }
        let want = self.entry_hash(&inode, name)?;
        if inode.inline_dentry() {
            let (at, len) = inode.inline_data_span();
            let l = Layout::inline(len);
            let mut block = self.inode_bytes(dir)?;
            let hit = deblock::find(&block[at..at + len], &l, want, name)
                .map_err(|_| Errno::Eio)?
                .ok_or(Errno::Enoent)?;
            let ino = clear_entry(&mut block[at..at + len], &l, hit.slot).ok_or(Errno::Eio)?;
            self.put_inode(dir, block)?;
            return Ok(ino);
        }
        let l = Layout::block();
        let depth = inode.current_depth.min(MAX_LOOKUP_DEPTH);
        for level in 0..depth {
            for index in bucket::search_range(want, level, inode.dir_level) {
                let Mapped::At(addr) = self.map_block(&inode, dir, index)? else { continue };
                let mut area = self.read_main_block(addr)?;
                let Some(hit) = deblock::find(&area, &l, want, name).map_err(|_| Errno::Eio)?
                    else { continue };
                let ino = clear_entry(&mut area, &l, hit.slot).ok_or(Errno::Eio)?;
                // A block emptied of every entry is released rather than left
                // allocated: a directory that only ever grows never shrinks.
                if area_is_empty(&area, &l) {
                    self.release_block(addr)?;
                    let (holder, ofs) = self.dnode_for_write(dir, index)?;
                    self.set_holder_addr(dir, holder, ofs, NULL_ADDR)?;
                } else {
                    self.write_one_block(dir, index, 0, &area)?;
                }
                let blocks = self.count_blocks(dir)?;
                self.stamp_inode(dir, |b| Self::set_iblocks(b, blocks))?;
                return Ok(ino);
            }
        }
        Err(Errno::Enoent)
    }
}

impl<S: SectorSource> Volume<S> {
    /// The hash an entry of `dir` is stored under.
    ///
    /// A folding directory hashes the FOLDED name, so every spelling reaches
    /// the same bucket; storing the raw hash makes the entry findable only by
    /// the spelling it was created with.
    /// # C: O(name len)
    pub(crate) fn entry_hash(&self, dir: &crate::node::Inode, name: &[u8]) -> Result<u32, Errno> {
        match (dir.casefolded(), self.casefold.as_ref()) {
            (true, Some(cf)) => Ok(crate::casefold::Query::prepare(cf, name)?.hash()),
            _ => Ok(hash::name_hash(name)),
        }
    }
}

/// The entries an inline area holds, for a caller that already has the block.
/// # C: O(entries)
pub fn inline_entries(block: &[u8], at: usize, len: usize) -> Result<Vec<deblock::Entry>, Errno> {
    deblock::entries(&block[at..at + len], &Layout::inline(len)).map_err(|_| Errno::Eio)
}

#[cfg(test)]
#[path = "../tests/dirwrite.rs"]
mod tests;
