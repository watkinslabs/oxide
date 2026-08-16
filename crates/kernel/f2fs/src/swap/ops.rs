//! Turning a file into a swap area, and turning it back.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::{FEATURE_BLKZONED, F2FS_COMPR_FL};
use crate::mode;
use crate::opts::Mode;
use crate::uapi::*;
use crate::volume::dnode::put32;
use crate::volume::map::Mapped;
use crate::volume::Volume;

use super::extents::{self, SwapMap};
use super::policy::{self, SwapFacts};

/// Passes the alignment walk may make over one file offset before it gives up.
///
/// The walk re-reads the map after moving a run, and a move that has not made
/// the run aligned would send it round again forever. Two is enough for the
/// move the reference makes; a third means the move did not do what it said.
const MAX_ALIGN_PASSES: u32 = 2;

impl<S: SectorSource> Volume<S> {
    /// What the activation decision reads. # C: O(1 block)
    pub fn swap_facts(&self, ino: u32) -> Result<SwapFacts, Errno> {
        let inode = self.read_inode(ino)?;
        Ok(SwapFacts {
            is_reg: mode::file_type(inode.mode) == vfs::FileType::Regular,
            ro_mount: !self.writable,
            lfs_mode: self.opts.mode == Mode::Lfs,
            blkzoned: self.sb.feature & FEATURE_BLKZONED != 0,
            compressed_undisableable: inode.compressed() && inode.blocks > 1,
        })
    }

    /// Make `ino` a swap area of at most `max` blocks, and report its runs.
    ///
    /// The file is PINNED on success and stays pinned until deactivation: the
    /// addresses in the returned map are the whole interface, and every
    /// mechanism that would move a block has to be told not to.
    /// # C: O(blocks in the file), plus any run that has to be moved
    pub fn swap_activate(&mut self, ino: u32, max: u64) -> Result<SwapMap, Errno> {
        policy::swap_activate(&self.swap_facts(ino)?)?;
        // A compressed file with nothing compressed stored stops being
        // compressed; one that holds compressed blocks was refused above.
        if self.read_inode(ino)?.compressed() {
            self.stamp_inode(ino, |b| {
                let flags = le32(b, I_FLAGS).unwrap_or(0) & !F2FS_COMPR_FL;
                put32(b, I_FLAGS, flags);
            })?;
        }
        // A file whose bytes are inside its own inode has no addresses at all.
        self.convert_inline(ino)?;
        let map = self.build_swap_map(ino, max)?;
        self.mark_pinned(ino, true)?;
        Ok(map)
    }

    /// Give up the area. The file stops being pinned, which is what lets the
    /// cleaner have its blocks again.
    /// # C: O(1 block)
    pub fn swap_deactivate(&mut self, ino: u32) -> Result<(), Errno> {
        if !self.writable { return Ok(()); }
        self.mark_pinned(ino, false)
    }

    /// Walk the file's blocks into runs, moving what is not aligned.
    /// # C: O(blocks in the file)
    fn build_swap_map(&mut self, ino: u32, max: u64) -> Result<SwapMap, Errno> {
        let per_sec = self.blks_per_sec();
        let main = self.sb.main_blkaddr;
        let last = self.read_inode(ino)?.size / BLKSIZE as u64;
        let mut map = SwapMap::default();
        let mut cur = 0u64;
        let mut lowest: Option<u32> = None;
        let mut highest = 0u32;
        let mut passes = 0u32;
        let mut last_extent = false;
        while cur < last && cur < max {
            let (pblk, run) = self.contiguous_run(ino, cur, last - cur)?;
            let mut nr = run;
            if !last_extent && !extents::section_aligned(pblk, main, nr, per_sec) {
                passes += 1;
                if passes > MAX_ALIGN_PASSES { return Err(Errno::Einval); }
                map.not_aligned += 1;
                nr = extents::roundup_sections(nr, per_sec);
                if cur + nr > max { nr = nr.saturating_sub(u64::from(per_sec)); }
                if nr == 0 {
                    // No whole section fits before the caller's ceiling, so
                    // the rest of the file is handed over as it lies: moving
                    // it would take space the area cannot then use.
                    nr = last - cur;
                    last_extent = true;
                }
                self.migrate_pinned_range(ino, cur, nr)?;
                continue;
            }
            passes = 0;
            if cur + nr >= max { nr = max - cur; }
            if nr == 0 { break; }
            // The file's first block is the area's header and is never paged,
            // so it is left out of the span the caller measures seeks by.
            if cur > 0 {
                lowest = Some(lowest.map_or(pblk, |l| l.min(pblk)));
                highest = highest.max(pblk + (nr as u32) - 1);
            }
            map.push(cur, pblk, nr);
            cur += nr;
        }
        map.seal(cur, lowest, highest);
        Ok(map)
    }

    /// The run of consecutive blocks the file has at `first`, up to `limit`.
    ///
    /// A hole is refused rather than skipped: the paging code is being handed
    /// addresses, and an index with no address is one it would read anyway.
    /// # C: O(run length) node reads
    fn contiguous_run(&self, ino: u32, first: u64, limit: u64) -> Result<(u32, u64), Errno> {
        let inode = self.read_inode(ino)?;
        let start = match self.map_block(&inode, ino, first)? {
            Mapped::At(a) => a,
            _ => return Err(Errno::Einval),
        };
        let mut nr = 1u64;
        while nr < limit {
            let want = u64::from(start) + nr;
            let Ok(u32_want) = u32::try_from(want) else { break };
            match self.map_block(&inode, ino, first + nr)? {
                Mapped::At(a) if a == u32_want => nr += 1,
                _ => break,
            }
        }
        Ok((start, nr))
    }
}
