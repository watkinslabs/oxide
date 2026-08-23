//! Metadata blocks, fetched before they are asked for.
//!
//! Four kinds of metadata get read in windows: the checkpoint pack, the
//! segment table, the node table and the summary area. They are four kinds
//! rather than one because an index means something different in each: two of
//! them index a TABLE, whose block address depends on which copy the version
//! bitmap currently selects, and two index the medium directly.
//!
//! The window stops at the first index the kind may not reach and reports how
//! many blocks it got. Stopping rather than skipping is the point: a window is
//! contiguous, so an index past the end of an area means every index after it
//! is too, and continuing would read the next area's blocks under this area's
//! name.

use sectors::SectorSource;

use crate::uapi::{BLKSIZE, NAT_ENTRY_PER_BLOCK, SIT_ENTRY_PER_BLOCK};

use super::super::Volume;
use super::window::{meta_index_ok, nat_ra_index, nat_ra_nid, sit_ra_segno, Areas, RaMeta};

impl<S: SectorSource> Volume<S> {
    /// Where this volume's areas begin and end. # C: O(1)
    pub(crate) fn ra_areas(&self) -> Areas {
        let bps = self.sb.blks_per_seg();
        Areas {
            cp_start: self.cp.start(self.sb.cp_blkaddr, bps),
            sit_start: self.sb.sit_blkaddr,
            sit_blocks: self.sb.segment_count_main.div_ceil(SIT_ENTRY_PER_BLOCK as u32),
            ssa_start: self.sb.ssa_blkaddr,
            main_start: self.sb.main_blkaddr,
            nat_blocks: self.max_nid() / NAT_ENTRY_PER_BLOCK as u32,
            main_end: self.sb.max_blkaddr() as u32,
        }
    }

    /// Fetch `nrpages` metadata blocks of kind `ty` from index `start`,
    /// reporting how many indexes the window covered before it stopped.
    ///
    /// Best-effort in every direction: a block that will not read leaves the
    /// mapping as it was and does not end the window, because the blocks after
    /// it are still worth having, and no failure reaches the caller. The count
    /// is what the reference returns for the one caller that needs it — a
    /// recovery scan, which reads exactly as far as the window reached.
    /// # C: O(nrpages) blocks
    pub fn ra_meta_pages(&self, start: u32, nrpages: u32, ty: RaMeta) -> u32 {
        let a = self.ra_areas();
        let mut blkno = start;
        // Resolved first, fetched second, for the reason every readahead here
        // does it: the table blocks a window covers are laid out next to each
        // other, so a resolved window collapses into a handful of transfers
        // where a block-at-a-time loop would issue one per block.
        let mut addrs: alloc::vec::Vec<Option<u32>> = alloc::vec::Vec::new();
        for _ in 0..nrpages {
            if !meta_index_ok(ty, blkno, &a) { break; }
            let Some(addr) = self.ra_meta_addr(blkno, ty, &a) else { break };
            addrs.push(self.ra_meta_wanted(addr, ty));
            blkno = blkno.wrapping_add(1);
        }
        for run in super::window::runs(&addrs) { self.ra_meta_run(run.addr, run.len, ty); }
        blkno - start
    }

    /// The block one metadata readahead index names.
    ///
    /// The two table kinds resolve through the version bitmap, so readahead
    /// fetches the copy a reader would go to. Fetching the other one would
    /// fill the mapping with the stale half of the table, and every read after
    /// it would be answered from there.
    /// # C: O(1)
    fn ra_meta_addr(&self, blkno: u32, ty: RaMeta, a: &Areas) -> Option<u32> {
        let bps = self.sb.blks_per_seg();
        let addr = match ty {
            RaMeta::Nat => {
                let idx = nat_ra_index(blkno, a.nat_blocks);
                crate::nat::block_addr(self.sb.nat_blkaddr, bps,
                                       nat_ra_nid(idx, NAT_ENTRY_PER_BLOCK as u32),
                                       &self.nat_bitmap)
            }
            RaMeta::Sit => crate::sit::block_addr(
                self.sb.sit_blkaddr,
                crate::sit::area_blocks(self.sb.segment_count_sit, bps),
                sit_ra_segno(blkno, SIT_ENTRY_PER_BLOCK as u32),
                &self.sit_bitmap),
            RaMeta::Ssa | RaMeta::Cp | RaMeta::Por => blkno,
        };
        if u64::from(addr) >= self.sb.max_blkaddr() { return None; }
        Some(addr)
    }

    /// Whether readahead has anything to do for this address.
    ///
    /// Only the span the mapping covers is worth fetching: a block outside it
    /// has nowhere to be filed, so the read would be work with no result.
    /// Recovery's main-area blocks use the cache's temporary POR view, which
    /// gives them a filing without widening the ordinary metadata mapping.
    /// # C: O(1)
    fn ra_meta_wanted(&self, addr: u32, ty: RaMeta) -> Option<u32> {
        let por = ty == RaMeta::Por;
        if (por && !self.meta_cache.covers_por(addr))
            || (!por && !self.meta_cache.covers(addr)) { return None; }
        let held = if por { self.meta_cache.load_por(addr) }
                   else { self.meta_cache.load(addr) };
        if held.is_some() { return None; }
        Some(addr)
    }

    /// Put `len` consecutive metadata blocks in the mapping, as ONE transfer.
    /// # C: O(len * BLKSIZE)
    fn ra_meta_run(&self, addr: u32, len: usize, ty: RaMeta) {
        if len == 0 { return; }
        let last = u64::from(addr) + len as u64 - 1;
        if last >= self.sb.max_blkaddr() { return; }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) { return; }
        let mut buf = alloc::vec![0u8; len * BLKSIZE];
        if self.source.read_sectors(u64::from(addr), &mut buf).is_err() { return; }
        for j in 0..len {
            let at = addr + j as u32;
            if ty == RaMeta::Por {
                self.meta_cache.store_por(at, &buf[j * BLKSIZE..(j + 1) * BLKSIZE]);
            } else {
                self.meta_cache.store(at, &buf[j * BLKSIZE..(j + 1) * BLKSIZE]);
            }
            self.io_account(crate::stats::iostat::Io::FsMetaRead, BLKSIZE as u64, false);
        }
    }
}
