//! Reconciling a drive's write pointers with what this filesystem believes
//! it has written.
//!
//! A sequential zone takes a write only at its write pointer. The pointer is
//! the DRIVE's state and the segment tables are the FILESYSTEM's, and a crash
//! can leave the two disagreeing in either direction: blocks the drive has
//! taken that the filesystem does not count, or blocks the filesystem counts
//! that the drive has not been given. Neither is a read error and neither is
//! visible until the next write to that zone is refused — which is why a
//! mount reconciles them rather than waiting to find out.
//!
//! Only two pairings are consistent, and they are consistent for opposite
//! reasons: an EMPTY zone holding no live block, and a FULL zone holding at
//! least one. Everything else is a disagreement, and there are exactly two
//! repairs:
//!
//! - **No live block, pointer moved.** Nothing in the zone is wanted, so the
//!   zone is RESET and the pointer goes back to the start. This is the common
//!   case after a crash mid-write.
//! - **Live blocks, pointer in the wrong place.** The blocks are wanted, so
//!   the zone is FINISHED — filled to its end and closed. That loses no data:
//!   the zone simply stops being a candidate for allocation until something
//!   discards it, which is exactly what a zone whose accounting cannot be
//!   trusted should be.
//!
//! Two zones are deliberately skipped. One outside the main area is not this
//! filesystem's to reconcile, and one a CURRENT LOG stands in is the log's
//! own business — the log's pointer is checked separately, against the same
//! drive, and repairing it from both sides would have the zone reset out from
//! under a log that is about to write to it.
//!
//! Everything here is a decision over stated facts. Nothing reads a device:
//! the caller does that, applies what this returns, and reads the drive again
//! where the reference does.

use super::report::ZoneCond;

/// What a zone needs doing to it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fix {
    /// The drive and the filesystem agree, or the zone is not this check's.
    Nothing,
    /// Send the pointer back to the start of the zone, discarding it.
    Reset,
    /// Fill the zone to its end and close it.
    Finish,
}

/// What one zone is, at the moment it is checked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ZoneFacts {
    /// Whether the drive REQUIRES sequential writes here. A host-aware zone
    /// is not reconciled: the drive accepts a write anywhere in it, so its
    /// pointer says nothing about what this filesystem may do.
    pub seq_required: bool,
    /// Whether the zone's first block falls inside the main area.
    pub in_main: bool,
    /// Whether a current log stands in this zone's section.
    pub is_cursec: bool,
    /// Live blocks in that section.
    pub valid_blocks: u32,
    pub cond: ZoneCond,
}

/// What to do about one zone. # C: O(1)
pub fn check_zone(f: ZoneFacts) -> Fix {
    if !f.seq_required || !f.in_main || f.is_cursec { return Fix::Nothing; }
    let empty = f.valid_blocks == 0;
    if empty && f.cond == ZoneCond::Empty { return Fix::Nothing; }
    if !empty && f.cond == ZoneCond::Full { return Fix::Nothing; }
    if empty { Fix::Reset } else { Fix::Finish }
}

/// What a current log's own zone is, at the moment it is checked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CursegFacts {
    /// Whether the drive requires sequential writes in the log's zone.
    pub seq_required: bool,
    /// Whether the last mount ended in a clean unmount.
    ///
    /// This is what decides whether the log's recorded position may be
    /// TRUSTED. After a clean unmount it was written by the checkpoint that
    /// closed the volume, so a log that matches the drive is left where it
    /// is. After a crash it was written by an older checkpoint and the writes
    /// since are unaccounted, so the log moves whatever the drive says.
    pub clean_umount: bool,
    /// Where the log stands, by the checkpoint's account.
    pub cs_segno: u32,
    pub cs_next_blkoff: u16,
    /// Where the drive will take the next write in that zone.
    pub wp_segno: u32,
    pub wp_blkoff: u16,
    /// Whether the drive's pointer sits inside a block rather than on one.
    pub wp_partial: bool,
    /// The first segment of the log's own zone.
    pub zone_first_segno: u32,
}

/// Whether the log may be left exactly where the checkpoint put it.
///
/// True only under the one condition that makes the recorded position
/// trustworthy: a clean unmount, and a drive whose pointer is at the same
/// block. A pointer part way into a block is NOT the same block — the drive
/// has taken bytes the log does not know about, and a log that appended there
/// would write over them.
/// # C: O(1)
pub fn curseg_agrees(f: CursegFacts) -> bool {
    if !f.seq_required { return true; }
    if !f.clean_umount { return false; }
    f.cs_segno == f.wp_segno && f.cs_next_blkoff == f.wp_blkoff && !f.wp_partial
}

/// Whether the log must be moved to a fresh section.
///
/// A log already at the very head of its own zone needs no move: a fresh zone
/// is exactly what it would be given. Any other position is one the drive may
/// refuse, so the log is opened somewhere the drive will certainly take.
/// # C: O(1)
pub fn needs_new_section(f: CursegFacts) -> bool {
    f.cs_next_blkoff != 0 || f.cs_segno != f.zone_first_segno
}

/// Whether the zone a log has just been given still has to be discarded.
///
/// A freshly chosen section is free as far as the FILESYSTEM is concerned,
/// which says nothing about the DRIVE: a zone whose blocks were released
/// without the drive being told still has its pointer part way along, and the
/// log's first write there would be refused.
/// # C: O(1)
pub fn new_zone_needs_reset(seq_required: bool, at_start: bool) -> bool {
    seq_required && !at_start
}

#[cfg(test)]
#[path = "../tests/zoned/wp.rs"]
mod tests;
