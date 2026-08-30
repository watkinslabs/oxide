// Unwritten -> written extent conversion for the write path.
//
// A `fallocate(2)` preallocation maps its range as UNWRITTEN extents: the
// blocks are allocated but read as zeros, never as the stale bytes still on
// the media. Writing into that range has to make the written part initialized
// WITHOUT publishing the rest, and without paying for the whole preallocation.

use alloc::vec;
use alloc::vec::Vec;

use crate::inode::Extent;
use crate::mount::{Mount, MountError};

use super::records::extent_run as mk_extent;

/// Largest range converted by zeroing the media instead of splitting the
/// extent, in kibibytes. Above it the extent is split so only the written
/// blocks become initialized and the untouched remainder keeps reading as
/// zeros for free.
///
/// Zeroing is O(range) device writes; splitting is O(1) metadata. Converting a
/// whole preallocation on its first write turns one 4 KiB write into thousands
/// of block writes — the cost `fallocate` exists to avoid.
pub(crate) const MAX_ZEROOUT_KB: u32 = 32;

impl Mount {
    /// Convert inline data to an extent file and apply the
    /// pending write. The caller is already inside the journal transaction
    /// opened by `write_at`; allocation and inode publication stay in the
    /// canonical extent inserter below, exactly as for an ordinary hole.
    /// # C: O(inline bytes + N extent allocations)
    pub(crate) fn convert_inline_data(
        &self, ino: u32, inode: &crate::inode::Inode, off: u64, data: &[u8],
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let off = usize::try_from(off).map_err(|_| MountError::BlockIo)?;
        let end = off.checked_add(data.len()).ok_or(MountError::BlockIo)?;
        let old_len = usize::try_from(inode.size).unwrap_or(bs).min(bs);
        let mut block = alloc::vec![0u8; bs];
        let old = if old_len != 0 {
            crate::mount::inline::read_inline_data(self, inode, 0, old_len)?
        } else { alloc::vec::Vec::new() };
        let new_size = if inode.is_dir() {
            let parent = if old.len() >= 4 {
                u32::from_le_bytes([old[0], old[1], old[2], old[3]])
            } else { return Err(MountError::BlockIo); };
            let mut entries = alloc::vec::Vec::new();
            entries.push((inode.ino, crate::dir::DT_DIR, b".".to_vec()));
            entries.push((parent, crate::dir::DT_DIR, b"..".to_vec()));
            let first_end = old.len().min(crate::inode::I_BLOCK_LEN);
            collect_inline_dirents(&old[4..first_end], &mut entries)?;
            if old.len() > crate::inode::I_BLOCK_LEN {
                collect_inline_dirents(&old[crate::inode::I_BLOCK_LEN..], &mut entries)?;
            }
            let usable = crate::csum::dir_usable_len(&self.sb, bs);
            write_dir_entries(&entries, &mut block, usable)?;
            crate::csum::stamp_dirent_tail(&self.sb, ino, inode.generation, &mut block);
            bs as u64
        } else { inode.size.max(end as u64) };
        let (mut bytes, inode_byte_off) = self.read_inode_bytes(ino)?;
        let isize = self.sb.inode_size as usize;
        let extra = ibody_extra_isize(&bytes, isize);
        if extra != 0 {
            let hdr = crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra;
            let mut entries = crate::xattr::decode_ibody(&bytes, hdr, isize);
            entries.retain(|(name, _)| name != "system.data");
            crate::xattr::encode_ibody(&mut bytes, hdr, isize, &entries)
                .map_err(|_| MountError::NotExtents)?;
        }
        let flags = u32::from_le_bytes([bytes[0x20], bytes[0x21], bytes[0x22], bytes[0x23]]);
        let flags = (flags | crate::inode::EXT4_EXTENTS_FL)
            & !crate::inode::EXT4_INLINE_DATA_FL;
        bytes[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        let mut root = [0u8; crate::inode::I_BLOCK_LEN];
        crate::inode::write_extent_header(&mut root, &crate::inode::ExtentHeader {
            magic: crate::inode::EXT4_EXT_MAGIC, entries: 0, max: 4, depth: 0, generation: 0,
        });
        bytes[0x28..0x28 + crate::inode::I_BLOCK_LEN].copy_from_slice(&root);
        if inode.is_dir() {
            self.insert_logical_block_with_inode_bytes(
                ino, &mut bytes, inode_byte_off, 0, &block, new_size, false, false, None,
            )?;
        } else {
            let blocks = (new_size.saturating_add(bs as u64 - 1) / bs as u64) as usize;
            for logical in 0..blocks {
                let block_start = logical * bs;
                let block_end = block_start.saturating_add(bs);
                let mut data_block = alloc::vec![0u8; bs];
                let old_start = block_start.min(old.len());
                let old_end = block_end.min(old.len());
                if old_end > old_start {
                    data_block[old_start - block_start..old_end - block_start]
                        .copy_from_slice(&old[old_start..old_end]);
                }
                let write_start = off.max(block_start);
                let write_end = end.min(block_end);
                if write_end > write_start {
                    data_block[write_start - block_start..write_end - block_start]
                        .copy_from_slice(&data[write_start - off..write_end - off]);
                }
                self.insert_logical_block_with_inode_bytes(
                    ino, &mut bytes, inode_byte_off, logical as u32, &data_block,
                    new_size, false, false, None,
                )?;
            }
        }
        Ok(())
    }

    /// Convert completed direct-I/O blocks from unwritten to initialized
    /// without zeroing them. The caller has already written every block in
    /// `ranges`; this is the metadata half of Linux's DIO `end_io` owner.
    /// # C: O(extents + range boundaries) + O(1) journal transaction
    pub(crate) fn convert_unwritten_range(
        &self, ino: u32, ranges: &[(u32, u32)],
    ) -> Result<(), MountError> {
        if ranges.is_empty() { return Ok(()); }
        self.run_journaled_deferred(|m| {
            let inode = m.read_inode(ino)?;
            let runs = m.collect_phys_extents(&inode.i_block)?;
            let mut out = Vec::with_capacity(runs.len() + ranges.len() * 2);
            let mut changed = false;
            for run in runs {
                if !run.unwritten {
                    out.push(mk_extent(run.logical, run.phys, run.len, false));
                    continue;
                }
                let start = u64::from(run.logical);
                let end = start + u64::from(run.len);
                let mut points = vec![start, end];
                for &(range_start, range_len) in ranges {
                    let rs = u64::from(range_start);
                    let re = rs.saturating_add(u64::from(range_len));
                    if rs < end && re > start {
                        points.push(core::cmp::max(rs, start));
                        points.push(core::cmp::min(re, end));
                    }
                }
                points.sort_unstable();
                points.dedup();
                for pair in points.windows(2) {
                    let part_start = pair[0];
                    let part_end = pair[1];
                    if part_start >= part_end { continue; }
                    let convert = ranges.iter().any(|&(range_start, range_len)| {
                        let rs = u64::from(range_start);
                        let re = rs.saturating_add(u64::from(range_len));
                        part_start >= rs && part_end <= re
                    });
                    changed |= convert;
                    out.push(mk_extent(
                        part_start as u32,
                        run.phys + part_start - start,
                        (part_end - part_start) as u32,
                        !convert,
                    ));
                }
            }
            if !changed { return Ok(()); }
            let (mut bytes, _) = m.read_inode_bytes(ino)?;
            m.write_extent_tree(ino, &mut bytes, &out).map(|_| ())
        })
    }

    /// Blocks convertible by zeroing rather than splitting, for this block size.
    /// # C: O(1)
    fn max_zeroout_blocks(&self) -> u32 {
        let bs = self.sb.block_size.max(1);
        ((MAX_ZEROOUT_KB * 1024) / bs).max(1)
    }

    /// Make `file_blk` initialized within its unwritten extent.
    ///
    /// Small extents are zeroed and converted whole; a larger one is SPLIT so
    /// only `file_blk` becomes written and the surrounding preallocation stays
    /// unwritten. Either way the converted block itself is zeroed first, so a
    /// caller that writes only part of it cannot expose the stale media bytes
    /// underneath — the guarantee the unwritten flag was carrying.
    ///
    /// No-op when `file_blk` maps to a written extent or a hole. MUST run
    /// inside a `run_journaled` scope (`write_at` does): the metadata change
    /// stages in the shadow and commits atomically, while the zeroing is direct
    /// data I/O sequenced before that commit.
    /// # C: O(1) metadata + O(converted blocks) zero I/O
    /// Check the already-loaded extent snapshot before touching the inode
    /// table again. Returns whether conversion changed the extent tree; the
    /// caller can refresh its snapshot only in that case. # C: O(1) when written/hole
    pub(crate) fn convert_unwritten_at_cached(
        &self, ino: u32, file_blk: u32, inode: &crate::inode::Inode,
    ) -> Result<bool, MountError> {
        // Legacy indirect mappings have no extent records to convert.  Their
        // initialized/uninitialized state is represented by the pointer tree,
        // and the indirect mapper is the owner of that format.
        if inode.i_flags & crate::inode::EXT4_EXTENTS_FL == 0 {
            return Ok(false);
        }
        let runs = self.collect_phys_extents(&inode.i_block)?;
        let Some(hit) = runs.iter().position(|r|
            r.unwritten && file_blk >= r.logical && file_blk < r.logical + r.len)
        else { return Ok(false); };                     // written extent, or a hole

        let (mut ibytes, _off) = self.read_inode_bytes(ino)?;

        let r = &runs[hit];
        let (es, phys, len) = (r.logical, r.phys, r.len);
        let split = len > self.max_zeroout_blocks();

        // Zero only what actually becomes written: the whole run when it is
        // small enough to convert wholesale, otherwise just the target block.
        let (zero_from, zero_len) = if split { (file_blk, 1) } else { (es, len) };
        self.zero_extent_blocks(phys + (zero_from - es) as u64, zero_len)?;

        let mut out: Vec<Extent> = Vec::with_capacity(runs.len() + 2);
        for (i, run) in runs.iter().enumerate() {
            if i != hit {
                out.push(mk_extent(run.logical, run.phys, run.len, run.unwritten));
                continue;
            }
            if !split {
                out.push(mk_extent(es, phys, len, false));
                continue;
            }
            // prefix (still unwritten) | the converted block | suffix (still unwritten)
            if file_blk > es {
                out.push(mk_extent(es, phys, file_blk - es, true));
            }
            out.push(mk_extent(file_blk, phys + (file_blk - es) as u64, 1, false));
            let tail = es + len;
            if file_blk + 1 < tail {
                out.push(mk_extent(file_blk + 1, phys + (file_blk + 1 - es) as u64,
                                   tail - (file_blk + 1), true));
            }
        }
        out.sort_unstable_by_key(|e| e.block);

        let (old_sectors, sectors) = self.write_extent_tree(ino, &mut ibytes, &out)?;
        if let Err(e) = self.write_inode_bytes_data(ino, &ibytes) {
            return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
        }
        Ok(true)
    }

    /// Zero `len` filesystem blocks starting at physical LBA `start_lba` —
    /// direct data write, not journaled: the not-yet-written blocks of an
    /// unwritten extent being initialized. # C: O(len) block I/O
    fn zero_extent_blocks(&self, start_lba: u64, len: u32) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let zero = alloc::vec![0u8; bs];
        for i in 0..len as u64 {
            self.write_data_byte_range((start_lba + i) * (bs as u64), &zero)?;
        }
        Ok(())
    }
}

fn collect_inline_dirents(
    bytes: &[u8], out: &mut alloc::vec::Vec<(u32, u8, alloc::vec::Vec<u8>)>,
) -> Result<(), MountError> {
    let mut off = 0usize;
    while off < bytes.len() {
        let (entry, next) = crate::dir::next_entry(bytes, off).map_err(MountError::Dir)?;
        if entry.inode != 0 {
            out.push((entry.inode, entry.file_type, entry.name.to_vec()));
        }
        off = next;
    }
    Ok(())
}

fn write_dir_entries(
    entries: &[(u32, u8, alloc::vec::Vec<u8>)], block: &mut [u8], usable: usize,
) -> Result<(), MountError> {
    let mut off = 0usize;
    for (idx, (ino, file_type, name)) in entries.iter().enumerate() {
        let actual = crate::dir::entry_actual_len(name.len() as u8);
        let rec_len = if idx + 1 == entries.len() { usable - off } else { actual };
        if name.len() > 255 || rec_len < actual || rec_len > u16::MAX as usize {
            return Err(MountError::Dir(crate::dir::DirError::BadNameLen));
        }
        block[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        block[off + 4..off + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
        block[off + 6] = name.len() as u8;
        block[off + 7] = *file_type;
        block[off + 8..off + 8 + name.len()].copy_from_slice(name);
        off += rec_len;
    }
    if off != usable { return Err(MountError::Dir(crate::dir::DirError::Overrun)); }
    Ok(())
}

fn ibody_extra_isize(raw: &[u8], inode_size: usize) -> usize {
    if inode_size <= crate::csum::EXT4_GOOD_OLD_INODE_SIZE { return 0; }
    let extra = u16::from_le_bytes([raw[0x80], raw[0x81]]) as usize;
    if crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra + 4 > inode_size { 0 } else { extra }
}
