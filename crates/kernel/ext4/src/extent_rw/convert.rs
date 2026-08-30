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
