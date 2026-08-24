//! What the placement decisions ask the volume, and what it does with the
//! answers.
//!
//! The decisions themselves are pure and live in `crate::place`. This is the
//! gathering: eleven states of one file and five counts of one volume, read
//! from the one place that owns each, plus the in-place write itself — the only
//! write in the filesystem that changes a block's contents without changing its
//! address.
//!
//! Three of the reference's inputs are answered by the SHAPE of this build
//! rather than by a stored flag, and each is answered here so the decision does
//! not have to guess:
//!
//! - A page under the cleaner never arrives here. The cleaner writes the blocks
//!   it moves straight into a log, so a page reaching the writeback path is
//!   never one being migrated.
//! - A file being aligned for a swap area, and a file being defragmented, both
//!   place every dirty page before they start, so neither state can coincide
//!   with a page arriving here either.
//! - A changed inode IS a dirty node page in this build, so the reference's
//!   separate count of dirty inode metadata is already inside the node count;
//!   adding it again would count the same pressure twice.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::{CP_CRC_RECOVERY_FLAG, CP_ERROR_FLAG, FADVISE_COLD_BIT};
use crate::node::Inode;
use crate::place::{ipu, ssr};
use crate::sbflags::bits;
use crate::uapi::{CURSEG_WARM_NODE, NR_CURSEG_DATA_TYPE};

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Maximum data blocks in one block-fragmentation chunk. # C: O(1)
    pub fn max_fragment_chunk(&self) -> u32 { self.max_fragment_chunk }

    /// Set the block-fragmentation chunk ceiling. # C: O(1)
    pub fn set_max_fragment_chunk(&mut self, value: u32) { self.max_fragment_chunk = value; }

    /// Maximum hole between block-fragmentation chunks. # C: O(1)
    pub fn max_fragment_hole(&self) -> u32 { self.max_fragment_hole }

    /// Set the block-fragmentation hole ceiling. # C: O(1)
    pub fn set_max_fragment_hole(&mut self, value: u32) { self.max_fragment_hole = value; }

    /// The pressure the recycling decision reads. # C: O(main segments)
    pub(crate) fn ssr_state(&self) -> ssr::Need {
        let per_sec = self.blks_per_sec();
        ssr::Need {
            lfs: self.opts.mode == crate::opts::Mode::Lfs,
            gc_urgent_high: self.gc_urgent_high(),
            cp_disabled: self.sbi.is_set(bits::CP_DISABLED),
            free_sections: self.free_section_count(),
            node_secs: ssr::secs_for_pages(self.node_cache.dirty(), per_sec),
            // Directory blocks are placed as they are changed rather than left
            // dirty in the mapping, so no directory ever holds a dirty data
            // page here and the dentry term is nothing to add.
            dent_secs: 0,
            imeta_secs: 0,
            min_ssr_sections: self.place.min_ssr_sections,
            reserved_sections: self.reserved_sections(),
        }
    }

    /// Whether the next allocation should recycle. # C: O(main segments)
    pub(crate) fn need_ssr(&self) -> bool { ssr::need_ssr(&self.ssr_state()) }

    /// Whether the cleaner has been put in its most urgent mode.
    ///
    /// Read from the background state the mount shares with its threads, which
    /// is where the knob that sets it writes. A volume driven without those
    /// threads — every hosted test — has none, and nothing is urgent.
    /// # C: O(1)
    pub(crate) fn gc_urgent_high(&self) -> bool {
        self.bg.as_ref().is_some_and(|b| b.gc_mode() == crate::bg::gc::GcMode::UrgentHigh)
    }

    /// The armed in-place-update policies. # C: O(1)
    pub fn ipu_policy(&self) -> u32 { self.place.ipu_policy }

    /// Arm a different set of in-place-update policies.
    ///
    /// Refuses rather than clamps, and the refusal is the decision module's
    /// (`crate::place::ipu::store_policy`): a mount that accepted a set it then
    /// ignored would report a policy that is not in force.
    /// # C: O(1)
    pub fn set_ipu_policy(&mut self, policy: u32) -> Result<(), Errno> {
        self.place.ipu_policy =
            ipu::store_policy(policy, self.opts.mode == crate::opts::Mode::Lfs)?;
        Ok(())
    }

    /// The occupancy the utilisation arms compare against. # C: O(1)
    pub fn min_ipu_util(&self) -> u32 { self.place.min_ipu_util }

    /// Retune it. # C: O(1)
    pub fn set_min_ipu_util(&mut self, value: u64) -> Result<(), Errno> {
        self.place.min_ipu_util = crate::place::tunables::store_threshold(value)?;
        Ok(())
    }

    /// Dirty pages at or below which an `fsync` asks for in-place writes.
    /// # C: O(1)
    pub fn min_fsync_blocks(&self) -> u32 { self.place.min_fsync_blocks }

    /// Retune it. # C: O(1)
    pub fn set_min_fsync_blocks(&mut self, value: u64) -> Result<(), Errno> {
        self.place.min_fsync_blocks = crate::place::tunables::store_threshold(value)?;
        Ok(())
    }

    /// The floor of free sections kept above the reserve before recycling
    /// starts. # C: O(1)
    pub fn min_ssr_sections(&self) -> u32 { self.place.min_ssr_sections }

    /// Retune it. # C: O(1)
    pub fn set_min_ssr_sections(&mut self, value: u64) -> Result<(), Errno> {
        self.place.min_ssr_sections = crate::place::tunables::store_threshold(value)?;
        Ok(())
    }

    /// Sections an ahead-of-demand cleaning pass costs before it settles.
    ///
    /// From the background state the mount shares with its threads, which is
    /// where the knob that sets it writes. A volume driven without those threads
    /// — every hosted test — has none and uses the value the mount would have
    /// started them with.
    /// # C: O(1)
    pub(crate) fn max_victim_search(&self) -> u32 {
        self.bg.as_ref().map_or(crate::volume::gc::victim::DEF_MAX_VICTIM_SEARCH,
                                |b| b.gc.lock().max_victim_search)
    }

    /// Give the volume the background state its mount's threads share.
    ///
    /// Late rather than at construction: the state is built from what the
    /// volume itself reports, so it cannot exist until the volume does.
    /// # C: O(1)
    pub fn attach_bg(&mut self, bg: alloc::sync::Arc<crate::bg::Bg>) { self.bg = Some(bg); }

    /// Everything the in-place decision reads, for one page of one file.
    ///
    /// `old` is the address the page currently occupies; `sync` says whether a
    /// caller is waiting on this write, which is what parts the asynchronous
    /// arm from the rest.
    /// # C: O(1 block) when checkpointing is off, O(1) otherwise
    pub(crate) fn ipu_facts(&self, ino: u32, inode: &Inode, old: u32, sync: bool)
        -> Result<ipu::Facts, Errno> {
        let cp_disabled = self.sbi.is_set(bits::CP_DISABLED);
        Ok(ipu::Facts {
            lfs: self.opts.mode == crate::opts::Mode::Lfs,
            need_fsck: self.sbi.is_set(bits::NEED_FSCK),
            cp_disabled,
            // Only asked in the one state that consults it: the answer costs a
            // read of the segment table as the medium holds it, and a mount
            // that is still checkpointing has no arm that reads it.
            checkpointed: cp_disabled && self.block_is_checkpointed(old)?,
            have_io: true,
            dir: inode.mode & crate::volume::fileops::mode_ifmt()
                == crate::volume::fileops::mode_ifdir(),
            quota: self.is_quota_file(ino),
            atomic: self.is_atomic_file(ino) || self.is_cow_file(ino),
            compressed: inode.compressed(),
            pinned: crate::pin::state::is_pinned(inode),
            cold: inode.advise & FADVISE_COLD_BIT != 0,
            opu_write: false,
            aligned_write: false,
            gcing: false,
            need_ipu: self.need_ipu == Some(ino),
            encrypted: inode.encrypted(),
            async_write: !sync,
            policy: self.place.ipu_policy,
            util: self.utilization(),
            min_ipu_util: self.place.min_ipu_util,
        })
    }

    /// Whether this page's write may land back on `old`.
    ///
    /// A slot holding no block at all is never a candidate: there is nothing to
    /// overwrite, and the reservation a deferred write left there is a promise
    /// of space rather than a block.
    /// # C: O(1), plus O(main segments) when a pressure arm is armed
    pub(crate) fn writes_in_place(&self, ino: u32, inode: &Inode, old: u32, sync: bool)
        -> Result<bool, Errno> {
        self.writes_in_place_kind(ino, inode, old, sync, inode.compressed())
    }

    /// Whether a page's stored cluster shape permits the ordinary in-place
    /// policy. A compressed inode may carry raw clusters; those pages are
    /// ordinary data and must not inherit the inode-wide image refusal.
    /// # C: O(1), plus O(main segments) when a pressure arm is armed
    pub(crate) fn writes_in_place_kind(&self, ino: u32, inode: &Inode, old: u32, sync: bool,
                                       compressed: bool) -> Result<bool, Errno> {
        if crate::node::is_hole(old) || crate::node::is_compressed(old) { return Ok(false); }
        if !self.sb_main_contains(old) { return Ok(false); }
        let mut f = self.ipu_facts(ino, inode, old, sync)?;
        f.compressed = compressed;
        Ok(ipu::need_inplace_update(&f, || self.need_ssr()))
    }

    /// Whether this file's writes would land back where they already are, asked
    /// by a caller that is about to MOVE its blocks.
    ///
    /// No block address and no write: this is the question about the file
    /// rather than about one page, so the arms that read a request's urgency or
    /// the block's checkpoint state have nothing to read and do not fire. The
    /// file counts as having asked for out-of-place writes, because that is
    /// what the caller is doing — so a mount that honours such a request is not
    /// stopped by its own in-place policy.
    /// # C: O(1), plus O(main segments) when a pressure arm is armed
    pub(crate) fn writes_in_place_opu(&self, ino: u32, inode: &Inode) -> Result<bool, Errno> {
        let mut f = self.ipu_facts(ino, inode, crate::uapi::NULL_ADDR, true)?;
        f.have_io = false;
        f.opu_write = true;
        Ok(ipu::should_update_inplace(&f, || self.need_ssr()))
    }

    /// Whether the segment table as the MEDIUM holds it names `addr` as live.
    ///
    /// The mount's own loaded table is not the question. What matters is
    /// whether the last checkpoint still describes this block, because that is
    /// the copy a crash would be recovered from — so the state this mount has
    /// changed since is exactly what has to be left out.
    /// # C: O(1 block)
    pub(crate) fn block_is_checkpointed(&self, addr: u32) -> Result<bool, Errno> {
        let Some(segno) = self.sb.segno_of(addr) else { return Ok(false) };
        let off = (addr - self.sb.main_blkaddr) % self.sb.blks_per_seg();
        let blocks = crate::sit::area_blocks(self.sb.segment_count_sit, self.sb.blks_per_seg());
        let at = crate::sit::block_addr(self.sb.sit_blkaddr, blocks, segno, &self.sit_bitmap);
        let block = self.read_block(at)?;
        let entry = crate::sit::resolve(&self.sit_journal, &block, segno).ok_or(Errno::Eio)?;
        Ok(entry.is_valid(off as usize))
    }

    /// Rewrite one block of a file's data WHERE IT LIES.
    ///
    /// Nothing about the volume's shape changes: the segment table already
    /// names the block as live, the summary entry already names the same owner
    /// and offset, and the file's own slot already holds this address. The
    /// bytes are the only thing that changes, which is what makes this write
    /// cost one block instead of one block plus every node above it.
    ///
    /// Two refusals, and both are the volume telling the caller it may not:
    /// a block whose segment does not hold DATA means the tables and the file
    /// disagree about what this address is, and rewriting it would put a file's
    /// bytes over a node or a summary; a volume whose checkpoint is already
    /// broken may not have more written into it at all.
    /// # C: O(1 block)
    pub(crate) fn write_data_in_place(&mut self, addr: u32, page: &[u8],
                                     flags: block::RequestFlags,
                                     ctx: Option<&block::crypto::Ctx>) -> Result<(), Errno> {
        if !self.data_segment(addr)? {
            self.sbi.set(bits::NEED_FSCK);
            return Err(Errno::Euclean);
        }
        if self.cp.flags & CP_ERROR_FLAG != 0 { return Err(Errno::Eio); }
        self.write_block_crypt(addr, page, flags, ctx)?;
        self.counters.borrow_mut().inc_inplace_blocks();
        // No checkpoint is owed by this write and the mark is not raised. The
        // segment table already counted this block, the summary already names
        // its owner and the file's slot already holds the address, so there is
        // nothing in memory a checkpoint would have to persist — which is the
        // whole saving, and claiming otherwise would make every rewritten byte
        // buy a checkpoint.
        {
            use crate::stats::iostat::Io;
            self.io_account(self.io_gc_kind(Io::FsData, Io::FsGcData),
                            crate::uapi::BLKSIZE as u64, false);
        }
        Ok(())
    }

    /// Whether the segment holding `addr` is one of the data logs.
    ///
    /// The type is the segment table's own record of which log filled it,
    /// stamped when a log opens the segment ([`Volume::stamp_seg_type`]). A
    /// data block whose segment says NODE means the file and the tables
    /// disagree about what this address is.
    /// # C: O(1 block)
    fn data_segment(&self, addr: u32) -> Result<bool, Errno> {
        let Some(segno) = self.sb.segno_of(addr) else { return Ok(false) };
        Ok(usize::from(self.seg_entry(segno)?.seg_type()) < NR_CURSEG_DATA_TYPE)
    }

    /// Record which log is filling `segno`.
    ///
    /// Written when a log OPENS a segment, which is the one moment the log and
    /// the segment are both known. Without it the type a volume was formatted
    /// with survives every reuse of the segment, so a segment that held nodes
    /// and now holds a file's data still reads as a node segment — and the
    /// guard above would refuse a legitimate write and demand a check of a
    /// healthy volume.
    /// # C: O(1)
    pub(crate) fn stamp_seg_type(&mut self, segno: u32, log: usize) {
        let ty = (log.min(usize::from(u8::MAX)) as u16) << crate::uapi::SIT_VBLOCKS_SHIFT;
        let Some(sit) = self.sit.as_mut() else { return };
        let Some(e) = sit.get_mut(segno as usize) else { return };
        let want = (e.vblocks & crate::uapi::SIT_VBLOCKS_MASK) | ty;
        if e.vblocks == want { return; }
        e.vblocks = want;
        self.sit_dirty.insert(segno);
    }

    /// Whether the log being reopened is the one a file's own node blocks go
    /// to, and whether the volume's checkpoints can be verified by a replay.
    /// # C: O(1)
    pub(crate) fn seg_choice(&self, log: usize, next_seg_free: bool) -> ssr::Choice {
        ssr::Choice {
            crc_recovery: self.cp.flags & CP_CRC_RECOVERY_FLAG != 0,
            warm_node_log: log == CURSEG_WARM_NODE,
            appending: self.curseg[log].alloc_type == crate::uapi::ALLOC_LFS,
            next_seg_free,
            cp_disabled: self.sbi.is_set(bits::CP_DISABLED),
        }
    }

    /// Whether the segment after `segno` is free AND inside the same section.
    ///
    /// The section bound is the point: appending into the next section means
    /// opening one, which is the very resource the recycling decision is trying
    /// to preserve — so a log at a section boundary gets no free pass.
    /// # C: O(logs + prefree)
    pub(crate) fn next_seg_free(&self, segno: u32) -> bool {
        let next = segno.wrapping_add(1);
        if next >= self.sb.segment_count_main { return false; }
        if next % self.sb.segs_per_sec.max(1) == 0 { return false; }
        self.seg_is_free(next)
    }
}

#[cfg(test)]
#[path = "../tests/placement.rs"]
mod tests;
