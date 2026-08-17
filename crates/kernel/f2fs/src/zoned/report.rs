//! What a drive says about its zones.
//!
//! This is a record of an answer, not a model: it is filled in from a device
//! that was asked, and a device that cannot be asked produces `None` rather
//! than a guess.

use alloc::vec::Vec;

/// What may be written where in one zone.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ZoneType {
    /// Writable anywhere, like an ordinary drive.
    Conventional,
    /// Writable only at the write pointer, and refused elsewhere.
    SeqWriteRequired,
    /// Writable anywhere, but the drive relocates what is not sequential.
    SeqWritePreferred,
}

impl ZoneType {
    /// Whether placement in this zone must follow the write pointer. Both
    /// sequential kinds count: a host-aware drive accepts a random write and
    /// then moves it, which loses the placement the filesystem chose.
    /// # C: O(1)
    pub fn sequential(self) -> bool { !matches!(self, ZoneType::Conventional) }
}

/// What a zone will accept right now.
///
/// Separate from [`ZoneType`], which says what the zone IS. A sequential zone
/// that is full refuses every write while remaining a sequential zone, and the
/// write-pointer check needs both answers: an empty zone with no live block is
/// consistent, a full zone with live blocks is consistent, and every other
/// pairing is a disagreement between the drive and this filesystem's idea of
/// what it holds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ZoneCond {
    /// Has no write pointer at all — only a conventional zone.
    NotWp,
    /// Written from the start, nothing in it yet.
    Empty,
    /// Open because a write opened it.
    ImplicitOpen,
    /// Open because it was asked to be.
    ExplicitOpen,
    /// Was open, is not now; its pointer is unchanged.
    Closed,
    /// Written to its capacity. Accepts no further write until reset.
    Full,
    /// Readable, never writable again.
    ReadOnly,
    /// Neither readable nor writable.
    Offline,
}

/// One zone, in the volume's block unit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Zone {
    pub start_blk: u64,
    pub len_blks: u32,
    /// Blocks of `len_blks` that may be written. Equal to the length on a
    /// zone that has no short capacity.
    pub cap_blks: u32,
    pub kind: ZoneType,
    /// Where the drive will take the next sequential write, RELATIVE to the
    /// start of the device, in volume blocks. `None` where the zone has no
    /// write pointer.
    ///
    /// Rounded DOWN, and `wp_partial` says whether anything was lost to the
    /// rounding. A drive whose blocks are smaller than the volume's can park
    /// its pointer inside a volume block, and a filesystem that read that as
    /// the block boundary would believe a log and a drive agree when the
    /// drive is half a block further on.
    pub wp_blk: Option<u64>,
    /// Whether the write pointer sits INSIDE a volume block rather than on
    /// its boundary.
    pub wp_partial: bool,
    pub cond: ZoneCond,
}

impl Zone {
    /// A zone as a drive that has never been written to reports it: a
    /// sequential zone's pointer is at its start and it is empty, and a
    /// conventional zone has no pointer at all.
    /// # C: O(1)
    pub fn fresh(start_blk: u64, len_blks: u32, cap_blks: u32, kind: ZoneType) -> Self {
        let seq = kind.sequential();
        Self {
            start_blk,
            len_blks,
            cap_blks,
            kind,
            wp_blk: if seq { Some(start_blk) } else { None },
            wp_partial: false,
            cond: if seq { ZoneCond::Empty } else { ZoneCond::NotWp },
        }
    }

    /// Blocks inside this zone that can never hold data. # C: O(1)
    pub fn unusable_blks(&self) -> u32 { self.len_blks.saturating_sub(self.cap_blks) }

    /// Whether the drive has written nothing in this zone. # C: O(1)
    pub fn at_start(&self) -> bool { self.wp_blk == Some(self.start_blk) && !self.wp_partial }
}

/// One member device's report.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DevZones {
    /// The zone size the drive states, in blocks. Every zoned member of one
    /// volume must state the same one.
    pub blocks_per_zone: u32,
    /// The most zones the drive will keep open at once, when it states a
    /// limit. `None` is no stated limit, which is what a drive that does not
    /// track open zones reports.
    pub max_open_zones: Option<u32>,
    pub zones: Vec<Zone>,
}

impl DevZones {
    /// The zone holding device-relative block `blk`, if this member has one.
    /// # C: O(zones)
    pub fn zone_at(&self, blk: u64) -> Option<&Zone> {
        self.zones.iter().find(|z| blk >= z.start_blk && blk < z.start_blk + u64::from(z.len_blks))
    }
}
