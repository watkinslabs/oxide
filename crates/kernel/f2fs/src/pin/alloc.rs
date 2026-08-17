//! The pinned section, and putting a pinned file's blocks in one.
//!
//! Pinning is refused on a file that already has blocks, so every block a
//! pinned file will ever own is allocated after the mark goes on, out of a
//! section opened for the purpose. That is the whole mechanism: the cleaner
//! chooses SECTIONS, so a section that holds only pinned blocks is a section
//! it will never empty, and one that holds a mixture is a section it can
//! neither clean nor leave alone.
//!
//! The log therefore rolls one segment at a time WITHIN a section and jumps to
//! a fresh section at its end, rather than taking whichever segment happened
//! to be free.

use alloc::vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::curseg::{Curseg, Kind};
use crate::volume::dnode::{put64, Holder};
use crate::volume::Volume;

use super::section;

impl<S: SectorSource> Volume<S> {
    /// Blocks one section holds, ignoring any zone capacity. # C: O(1)
    pub(crate) fn blks_per_sec(&self) -> u32 {
        crate::zoned::usable::blks_per_sec(&self.sb)
    }

    /// The first segment of the section `segno` belongs to. # C: O(1)
    pub(crate) fn section_of(&self, segno: u32) -> u32 {
        section::section_first(segno, self.sb.segs_per_sec)
    }

    /// The first wholly free section, searching from `hint` onwards.
    /// # C: O(main segments)
    pub(crate) fn find_free_section(&self, hint: u32) -> Option<u32> {
        section::find_free_section(hint, self.sb.segs_per_sec, self.sb.segment_count_main,
                                   |s| self.seg_is_free(s))
    }

    /// Give the pinned log somewhere to write.
    ///
    /// Within a section the log steps to the next segment; at a section's end
    /// it takes a fresh one. Stepping to whichever segment happened to be free
    /// would scatter one file's pinned blocks across sections the cleaner is
    /// otherwise free to choose, which is the promise this exists to keep.
    /// # C: O(main segments) when a section must be found
    pub(crate) fn open_pinned_section(&mut self) -> Result<(), Errno> {
        let log = CURSEG_COLD_DATA_PINNED;
        let per = self.sb.segs_per_sec.max(1);
        let old = self.curseg[log].segno;
        if old != NULL_SEGNO {
            // The summary block is the only record of who owns each block of
            // the segment being left. A pinned segment without one cannot be
            // checked, and its space cannot be accounted for.
            self.curseg[log].seal(false);
            let block = self.curseg[log].sum.clone();
            self.write_block(sum_block_addr(self.sb.ssa_blkaddr, old), &block)?;
            if let Some(next) =
                section::next_in_section(old, per, self.sb.segment_count_main) {
                self.curseg[log].segno = next;
                self.curseg[log].next_blkoff = 0;
                self.curseg[log].alloc_type = ALLOC_LFS;
                self.curseg[log].sum = vec![0u8; BLKSIZE];
                return Ok(());
            }
            if self.seg_valid(old) == 0 { self.retire_segment(old); }
        }
        let hint = if old == NULL_SEGNO { 0 } else { old };
        let reserve = self.gc_reserve();
        if !self.recovering && self.free_segment_count() <= reserve + per {
            let _ = self.collect(reserve + per + 1);
        }
        let first = self.find_free_section(hint).ok_or(Errno::Enospc)?;
        self.curseg[log].segno = first;
        self.curseg[log].next_blkoff = 0;
        self.curseg[log].alloc_type = ALLOC_LFS;
        self.curseg[log].sum = vec![0u8; BLKSIZE];
        Ok(())
    }

    /// Start a fresh pinned section, whatever the log was doing.
    ///
    /// A caller about to lay down a run that must be section-aligned needs the
    /// log at a section boundary; a log part way through one would put the run
    /// across two.
    /// # C: O(main segments)
    pub fn allocate_pinning_section(&mut self) -> Result<(), Errno> {
        self.writable_or_err()?;
        self.load_segments()?;
        let log = CURSEG_COLD_DATA_PINNED;
        let at_boundary = self.curseg[log].segno != NULL_SEGNO
            && self.curseg[log].next_blkoff == 0
            && self.section_of(self.curseg[log].segno) == self.curseg[log].segno;
        if at_boundary { return Ok(()); }
        // Nothing written yet: the log is closed rather than rolled, so the
        // opener takes a section instead of the next segment of this one.
        if self.curseg[log].segno != NULL_SEGNO && self.curseg[log].next_blkoff == 0 {
            let old = self.curseg[log].segno;
            if self.seg_valid(old) == 0 { self.retire_segment(old); }
            self.curseg[log] = Curseg::empty();
        } else if self.curseg[log].segno != NULL_SEGNO {
            self.curseg[log].seal(false);
            let block = self.curseg[log].sum.clone();
            let old = self.curseg[log].segno;
            self.write_block(sum_block_addr(self.sb.ssa_blkaddr, old), &block)?;
            self.curseg[log] = Curseg::empty();
        }
        self.open_pinned_section()
    }

    /// Give a pinned file real blocks for `[off, off + len)`.
    ///
    /// The run is widened to whole sections at both ends, which is what makes
    /// the file's addresses usable by a caller outside the filesystem: a
    /// swap area or a device mapper wants runs it can address, not a block
    /// here and a block there. Returns the blocks allocated.
    ///
    /// This is what a `fallocate` on a pinned file resolves to; a pinned file
    /// gets blocks no other way, because an ordinary write to one is refused
    /// unless it overwrites a block that already exists.
    /// # C: O(blocks allocated)
    pub fn expand_pinned(&mut self, ino: u32, off: u64, len: u64) -> Result<u64, Errno> {
        self.dquot_initialize(ino)?;
        self.writable_or_err()?;
        if len == 0 { return Ok(0); }
        let inode = self.read_inode(ino)?;
        if !crate::pin::state::is_pinned(&inode) { return Err(Errno::Einval); }
        let sec = u64::from(self.blks_per_sec());
        let end = off.checked_add(len).ok_or(Errno::Efbig)?;
        let first = (off / BLKSIZE as u64) / sec * sec;
        let last = end.div_ceil(BLKSIZE as u64);
        let count = (last - first).div_ceil(sec) * sec;
        self.allocate_pinning_section()?;
        let made = self.fill_pinned(ino, first, count, false)?;
        let size = end.max(self.read_inode(ino)?.size);
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| {
            put64(b, I_SIZE, size);
            Self::set_iblocks(b, blocks);
        })?;
        self.refresh_extent(ino)?;
        Ok(made)
    }

    /// Move `count` blocks of `ino` starting at `first` into a fresh pinned
    /// section, so the run begins and ends on a section boundary.
    ///
    /// A swap area needs its blocks section-aligned; a file that was pinned
    /// after it was written is not, and refusing it outright would refuse
    /// every swapfile that was created the ordinary way. Moving is legitimate
    /// here and nowhere else: the caller has not been told the addresses yet.
    /// # C: O(blocks moved)
    pub(crate) fn migrate_pinned_range(&mut self, ino: u32, first: u64, count: u64)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        if count == 0 { return Ok(()); }
        let sec = u64::from(self.blks_per_sec());
        let start = first / sec * sec;
        let stop = (first + count).div_ceil(sec) * sec;
        self.allocate_pinning_section()?;
        self.fill_pinned(ino, start, stop - start, true)?;
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))?;
        self.refresh_extent(ino)
    }

    /// Take `count` blocks out of the pinned log for `[first, first + count)`,
    /// keeping what is already there when `keep` is set.
    ///
    /// The addresses are written back a NODE at a time rather than one at a
    /// time. Every address of a file goes in one of a handful of blocks, and
    /// rewriting the holder per address costs a fresh block out of the log per
    /// address — on a whole section that is the section again, in node
    /// rewrites, and it breaks the very contiguity this call exists to
    /// produce.
    /// # C: O(count) blocks written
    fn fill_pinned(&mut self, ino: u32, first: u64, count: u64, keep: bool)
        -> Result<u64, Errno> {
        let zero = vec![0u8; BLKSIZE];
        let mut made = 0u64;
        let mut batch: alloc::vec::Vec<(usize, u32)> = alloc::vec::Vec::new();
        let mut group: Option<Holder> = None;
        for index in first..first + count {
            let (holder, ofs) = self.dnode_for_write(ino, index)?;
            if group != Some(holder) {
                if let Some(h) = group { self.put_addrs(ino, h, &batch)?; }
                batch.clear();
                group = Some(holder);
            }
            let old = self.holder_addr(ino, holder, ofs)?;
            let held = !crate::node::is_hole(old);
            if held && !keep { continue; }
            let page = if held { self.read_main_block(old)? } else { zero.clone() };
            if !held { self.charge_space(ino, BLKSIZE as u64)?; }
            let owner = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
            let released = if keep { old } else { NULL_ADDR };
            let addr =
                self.write_data_kind(Kind::PinnedData, owner, ofs as u16, released, &page)?;
            batch.push((ofs, addr));
            made += 1;
        }
        if let Some(h) = group { self.put_addrs(ino, h, &batch)?; }
        Ok(made)
    }

    /// Record several addresses in one node rewrite. # C: O(1 block)
    fn put_addrs(&mut self, ino: u32, holder: Holder, pairs: &[(usize, u32)])
        -> Result<(), Errno> {
        if pairs.is_empty() { return Ok(()); }
        // This path writes addresses in a BATCH rather than one at a time, so
        // it does not pass through the single-address funnel that tells the
        // caches. Telling them here is not optional: every pair below moves a
        // block, and a run left describing where the block used to be answers
        // a later read with data that has been overwritten by something else.
        for &(ofs, addr) in pairs { self.note_mapping_change(ino, holder, ofs, addr, true)?; }
        match holder {
            Holder::Inode => {
                let inode = self.read_inode(ino)?;
                let mut block = self.inode_bytes(ino)?;
                let base = inode.addr_base();
                for &(ofs, addr) in pairs {
                    if ofs >= inode.addrs_per_inode() { return Err(Errno::Efbig); }
                    block[base + ofs * 4..base + ofs * 4 + 4]
                        .copy_from_slice(&addr.to_le_bytes());
                }
                self.put_inode(ino, block)?;
                self.refresh_extent(ino)
            }
            Holder::Direct(nid) => {
                let mut block = self.read_node(nid, Some(ino))?.block;
                for &(ofs, addr) in pairs {
                    if ofs >= DEF_ADDRS_PER_BLOCK { return Err(Errno::Efbig); }
                    block[ofs * 4..ofs * 4 + 4].copy_from_slice(&addr.to_le_bytes());
                }
                let kind = self.node_kind(self.read_inode(ino)?.mode);
                self.write_node(nid, ino, block, kind)?;
                Ok(())
            }
        }
    }
}
