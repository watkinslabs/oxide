//! What the volume knows about a drive's zones, for the write-pointer check.
//!
//! The decision itself is `zoned::wp`; this is the half that reads the
//! segment tables, and the one place a log is moved because a DRIVE said so
//! rather than because it ran out of room.

use alloc::vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::{sum_block_addr, ALLOC_LFS, BLKSIZE, CURSEG_COLD_DATA_PINNED,
                  NR_CURSEG_DATA_TYPE, NULL_SEGNO};
use crate::zoned::report::Zone;
use crate::zoned::wp;

use super::Volume;

/// Keep the new-section search unconstrained by a boundary.
pub const ALLOCATE_FORWARD_NOHINT: u32 = 0;
/// Search from the beginning after crossing the boundary.
pub const ALLOCATE_FORWARD_WITHIN_HINT: u32 = 1;
/// Never search before the boundary.
pub const ALLOCATE_FORWARD_FROM_HINT: u32 = 2;
/// Prefer free sections in sequential zones.
pub const BLKZONE_ALLOC_PRIOR_SEQ: u32 = 0;
/// Refuse free sections in conventional zones while zoned allocation applies.
pub const BLKZONE_ALLOC_ONLY_SEQ: u32 = 1;
/// Prefer free sections in conventional zones.
pub const BLKZONE_ALLOC_PRIOR_CONV: u32 = 2;

impl<S: SectorSource> Volume<S> {
    /// Boundary section used by forward allocation. # C: O(1)
    pub fn allocate_section_hint(&self) -> u32 { self.allocate_section_hint }

    /// Set the forward-allocation boundary. # C: O(1)
    pub fn set_allocate_section_hint(&mut self, value: u64) -> Result<(), Errno> {
        if value > u64::from(u32::MAX) { return Err(Errno::Einval); }
        self.allocate_section_hint = value as u32;
        Ok(())
    }

    /// Forward allocation policy. # C: O(1)
    pub fn allocate_section_policy(&self) -> u32 { self.allocate_section_policy }

    /// Set the forward-allocation policy. # C: O(1)
    pub fn set_allocate_section_policy(&mut self, value: u64) -> Result<(), Errno> {
        if value > u64::from(ALLOCATE_FORWARD_FROM_HINT) { return Err(Errno::Einval); }
        self.allocate_section_policy = value as u32;
        Ok(())
    }

    /// Zoned regular-allocation preference. # C: O(1)
    pub fn blkzone_alloc_policy(&self) -> u32 { self.blkzone_alloc_policy }

    /// Set the zoned regular-allocation preference. # C: O(1)
    pub fn set_blkzone_alloc_policy(&mut self, value: u64) -> Result<(), Errno> {
        if value > u64::from(BLKZONE_ALLOC_PRIOR_CONV) { return Err(Errno::Einval); }
        self.blkzone_alloc_policy = value as u32;
        Ok(())
    }

    /// Apply Linux's boundary policy to a section search hint. # C: O(1)
    pub(crate) fn section_search_hint(&self, hint: u32) -> u32 {
        let per = self.sb.segs_per_sec.max(1);
        let mut section = crate::pin::section::section_first(hint, per) / per;
        let boundary = self.allocate_section_hint.min(self.sb.section_count);
        match self.allocate_section_policy {
            ALLOCATE_FORWARD_FROM_HINT if section < boundary => section = boundary,
            ALLOCATE_FORWARD_WITHIN_HINT if section >= boundary => section = 0,
            _ => {}
        }
        section.saturating_mul(per)
    }

    /// Whether a section begins in a sequential zone, when geometry says so.
    /// # C: O(1)
    pub(crate) fn section_is_sequential(&self, first: u32) -> Option<bool> {
        let geometry = self.zoned.as_ref()?;
        if geometry.blocks_per_zone == 0 { return None; }
        let block = u64::from(self.sb.main_blkaddr)
            + u64::from(first) * u64::from(self.sb.blks_per_seg());
        let (dev, local) = self.devs.target(u32::try_from(block).ok()?);
        Some(geometry.is_seq(dev, (local / geometry.blocks_per_zone) as usize))
    }

    /// First free section of the requested zone kind after `hint`. # C: O(main sections)
    fn find_free_section_kind(&self, hint: u32, sequential: bool) -> Option<u32> {
        let per = self.sb.segs_per_sec.max(1);
        let sections = self.sb.segment_count_main / per;
        let from = crate::pin::section::section_first(hint, per) / per;
        (from..sections).map(|section| section * per).find(|&first| {
            crate::pin::section::section_is_free(
                first, per, self.sb.segment_count_main, |seg| self.seg_is_free(seg),
            ) && self.section_is_sequential(first) == Some(sequential)
        })
    }

    /// Apply Linux's zoned allocation preference to a regular search.
    /// # C: O(main sections)
    fn find_policy_section(&self, hint: u32) -> Option<u32> {
        if self.zoned.is_none() { return self.find_free_section(hint); }
        match self.blkzone_alloc_policy {
            BLKZONE_ALLOC_ONLY_SEQ => {
                let first_seq = self.find_first_sequential_section();
                self.find_free_section_kind(first_seq, true)
            }
            BLKZONE_ALLOC_PRIOR_CONV => {
                self.find_free_section_kind(0, false)
                    .or_else(|| self.find_free_section(0))
            }
            _ => {
                let first_seq = self.find_first_sequential_section();
                self.find_free_section_kind(hint.max(first_seq), true)
                    .or_else(|| self.find_free_section(0))
            }
        }
    }

    /// First section whose drive zone is sequential. # C: O(main sections)
    fn find_first_sequential_section(&self) -> u32 {
        let per = self.sb.segs_per_sec.max(1);
        (0..self.sb.segment_count_main).step_by(per as usize)
            .find(|&first| self.section_is_sequential(first) == Some(true))
            .unwrap_or(self.sb.segment_count_main)
    }

    /// Whether a current log stands in the section beginning at `first`.
    ///
    /// A log's own zone is not reconciled by the zone sweep — it is settled
    /// against the same drive by the curseg pass, and repairing it from both
    /// sides would reset a zone out from under a log about to write to it.
    /// # C: O(logs)
    pub(crate) fn cursec_holds(&self, first: u32) -> bool {
        let per = self.sb.segs_per_sec.max(1);
        self.curseg.iter().any(|c| {
            c.segno != NULL_SEGNO && crate::pin::section::section_first(c.segno, per) == first
        })
    }

    /// The first segment of the ZONE that section `secno` belongs to.
    ///
    /// A zone can span several sections, so this is not the section's own
    /// first segment: a log at the head of the second section of a zone is
    /// part way into that zone, and the drive will not take a write at its
    /// start.
    /// # C: O(1)
    pub(crate) fn zone_first_segno(&self, secno: u32) -> u32 {
        let per_zone = self.sb.secs_per_zone.max(1);
        let per_sec = self.sb.segs_per_sec.max(1);
        (secno / per_zone) * per_zone * per_sec
    }

    /// What the segment tables say about the zone beginning at volume block
    /// `start`.
    ///
    /// The valid-block count is the SECTION's rather than the segment's: a
    /// zone holds whole sections, and a segment-sized answer would call a
    /// zone empty while a later segment of it still held live blocks.
    /// # C: O(segments per section)
    pub(crate) fn zone_facts(&mut self, start: u32, seq_required: bool,
                             cond: crate::zoned::ZoneCond) -> Result<wp::ZoneFacts, Errno> {
        self.load_segments()?;
        let per = self.sb.segs_per_sec.max(1);
        let Some(segno) = self.sb.segno_of(start) else {
            return Ok(wp::ZoneFacts {
                seq_required,
                in_main: false,
                is_cursec: false,
                valid_blocks: 0,
                cond,
            });
        };
        let first = crate::pin::section::section_first(segno, per);
        Ok(wp::ZoneFacts {
            seq_required,
            in_main: segno < self.sb.segment_count_main,
            is_cursec: self.cursec_holds(first),
            valid_blocks: self.section_valid(first),
            cond,
        })
    }

    /// Where the log `log` stands: its segment, or `NULL_SEGNO` when it
    /// stands nowhere yet. # C: O(1)
    pub(crate) fn curseg_segno(&self, log: usize) -> u32 { self.curseg[log].segno }

    /// How far into that segment the log has written. # C: O(1)
    pub(crate) fn curseg_blkoff(&self, log: usize) -> u16 { self.curseg[log].next_blkoff }

    /// The first block of the zone the log `log` stands in. # C: O(1)
    pub(crate) fn curseg_zone_block(&self, log: usize) -> Option<u32> {
        let segno = self.curseg_segno(log);
        if segno == NULL_SEGNO { return None; }
        let per = self.sb.segs_per_sec.max(1);
        let secno = crate::pin::section::section_first(segno, per) / per;
        let first = self.zone_first_segno(secno);
        Some(self.sb.main_blkaddr + first * self.sb.blks_per_seg())
    }

    /// Where the log stands and where the drive's pointer is, in the terms the
    /// decision is stated in.
    ///
    /// `zone` is the drive's report for the log's own zone, its addresses
    /// already made volume-relative by the caller — the member's own offset is
    /// not visible from here.
    /// # C: O(1)
    pub(crate) fn curseg_facts(&self, log: usize, zone: &Zone, clean_umount: bool)
        -> wp::CursegFacts {
        let per_seg = u64::from(self.sb.blks_per_seg().max(1));
        let per = self.sb.segs_per_sec.max(1);
        let cs_segno = self.curseg_segno(log);
        let secno = if cs_segno == NULL_SEGNO {
            0
        } else {
            crate::pin::section::section_first(cs_segno, per) / per
        };
        // The pointer is an ADDRESS on the volume; which segment it falls in
        // and how far into that segment are both derived from it, never read
        // off the log — that is exactly the pair being compared.
        let (wp_segno, wp_blkoff) = match zone.wp_blk {
            Some(wp) => {
                let rel = wp.saturating_sub(u64::from(self.sb.main_blkaddr));
                let segno = (rel / per_seg) as u32;
                (segno, (rel % per_seg) as u16)
            }
            None => (NULL_SEGNO, 0),
        };
        wp::CursegFacts {
            seq_required: zone.kind == crate::zoned::ZoneType::SeqWriteRequired,
            clean_umount,
            cs_segno,
            cs_next_blkoff: self.curseg_blkoff(log),
            wp_segno,
            wp_blkoff,
            wp_partial: zone.wp_partial,
            zone_first_segno: self.zone_first_segno(secno),
        }
    }

    /// Move the log `log` to a section nothing is using.
    ///
    /// The same shape as running out of room, with one difference that is the
    /// whole point: a SECTION is taken, never the next free segment. A zoned
    /// volume's zone holds whole sections, so a log handed a segment part way
    /// through one would be pointed at a zone the drive has already been
    /// written into.
    /// # C: O(main segments)
    pub(crate) fn open_new_section(&mut self, log: usize) -> Result<(), Errno> {
        self.writable_or_err()?;
        self.load_segments()?;
        // The pinned log has its own opener, and it already takes a section.
        if log == CURSEG_COLD_DATA_PINNED { return self.allocate_pinning_section(); }
        let old = self.curseg[log].segno;
        if old != NULL_SEGNO {
            // The summary block is the only record of which node owns each
            // block of the segment being left. A segment closed without one
            // cannot be cleaned, and its space is lost for the life of the
            // filesystem.
            self.curseg[log].seal(log >= NR_CURSEG_DATA_TYPE);
            let block = self.curseg[log].sum.clone();
            self.write_block(sum_block_addr(self.sb.ssa_blkaddr, old), &block)?;
            self.retire_segment(old);
        }
        let hint = if old == NULL_SEGNO { 0 } else { old };
        let per = self.sb.segs_per_sec.max(1);
        let reserve = self.gc_reserve();
        if !self.recovering && self.free_segment_count() <= reserve + per {
            let _ = self.collect(reserve + per + 1);
        }
        let first = self.find_policy_section(self.section_search_hint(hint))
            .ok_or(Errno::Enospc)?;
        self.curseg[log].segno = first;
        self.curseg[log].next_blkoff = 0;
        self.curseg[log].alloc_type = ALLOC_LFS;
        self.curseg[log].sum = vec![0u8; BLKSIZE];
        self.dirty = true;
        Ok(())
    }
}
