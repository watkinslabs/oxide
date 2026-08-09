// Unwritten -> written extent conversion for the write path.
//
// A `fallocate(2)` preallocation maps its range as UNWRITTEN extents: the
// blocks are allocated but read as zeros, never as the stale bytes still on
// the media. Writing into that range has to make the written part initialized
// WITHOUT publishing the rest, and without paying for the whole preallocation.

use alloc::vec::Vec;

use crate::inode::{Extent, I_BLOCK_LEN};
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
    pub(crate) fn convert_unwritten_at(&self, ino: u32, file_blk: u32) -> Result<(), MountError> {
        let (mut ibytes, _off) = self.read_inode_bytes(ino)?;
        let mut i_block = [0u8; I_BLOCK_LEN];
        i_block.copy_from_slice(&ibytes[0x28..0x28 + I_BLOCK_LEN]);

        let runs = self.collect_phys_extents(&i_block)?;
        let Some(hit) = runs.iter().position(|r|
            r.unwritten && file_blk >= r.logical && file_blk < r.logical + r.len)
        else { return Ok(()); };                       // written extent, or a hole

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
        if let Err(e) = self.write_inode_bytes(ino, &ibytes) {
            return Err(self.rollback_i_blocks_delta(ino, sectors, old_sectors, e));
        }
        Ok(())
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
