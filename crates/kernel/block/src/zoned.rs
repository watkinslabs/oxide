//! What a drive says about its zones.
//!
//! A zoned drive divides its capacity into zones. A conventional zone behaves
//! like ordinary storage; a sequential zone accepts writes only at its write
//! pointer, and may present a CAPACITY smaller than its length, leaving a tail
//! of addresses that exist and can never be written.
//!
//! A filesystem placed on such a drive must know this map exactly. It cannot
//! be inferred: two drives with the same capacity can have different zone
//! sizes, and two zones on one drive can have different capacities. So the
//! only source of a zone map is the drive, and a driver that has not been
//! taught to ask reports `None` — which every caller must read as "this is not
//! a zoned drive", never as "assume the usual layout".

use alloc::vec::Vec;

/// What may be written where in one zone.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ZoneType {
    /// Writable anywhere, like an ordinary drive.
    Conventional,
    /// Writable only at the write pointer; anything else is refused.
    SeqWriteRequired,
    /// Writable anywhere, but the drive relocates what is not sequential.
    SeqWritePreferred,
}

impl ZoneType {
    /// Whether placement here must follow the write pointer. # C: O(1)
    pub fn sequential(self) -> bool { !matches!(self, ZoneType::Conventional) }
}

/// What a zone will accept right now.
///
/// Separate from [`ZoneType`], which says what the zone IS. A sequential zone
/// that is full refuses every write while still being a sequential zone, and
/// a caller choosing where to place data needs both answers.
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

/// One zone, in units of the device's own block size.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Zone {
    pub start_block: u64,
    pub len_blocks: u64,
    /// Blocks of `len_blocks` that may hold data. Equal to the length on a
    /// zone with no short capacity.
    pub capacity_blocks: u64,
    pub kind: ZoneType,
    /// The only block a sequential write may target, when the zone has one.
    ///
    /// `None` means no write pointer exists — a conventional zone, which
    /// takes a write anywhere, or a read-only/offline zone, which takes none.
    /// The two are told apart by `cond`, never by this field alone.
    pub wp_block: Option<u64>,
    pub cond: ZoneCond,
}

impl Zone {
    /// Whether a write of `len_blocks` at `at` is one the drive will accept.
    ///
    /// The rule the whole type exists for. A sequential zone takes a write
    /// only at its write pointer, and only as far as its CAPACITY — not its
    /// length, which on a short-capacity zone runs past the last writable
    /// block. A conventional zone takes any write inside itself.
    /// # C: O(1)
    pub fn accepts_write(&self, at: u64, len_blocks: u64) -> bool {
        if matches!(self.cond, ZoneCond::ReadOnly | ZoneCond::Offline) { return false; }
        let Some(end) = at.checked_add(len_blocks) else { return false; };
        let writable_end = self.start_block.saturating_add(self.capacity_blocks);
        if at < self.start_block || end > writable_end { return false; }
        if !self.kind.sequential() { return true; }
        self.wp_block == Some(at)
    }
}

/// A zone-state transition a caller may ask the drive to make. Named for the
/// drive commands rather than for any filesystem's use of them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ZoneMgmtOp {
    /// Take the resources to write this zone before writing it.
    Open,
    /// Give those resources back; the write pointer stays where it is.
    Close,
    /// Move the write pointer to the end. The zone becomes full.
    Finish,
    /// Move the write pointer back to the start, discarding the zone.
    Reset,
    /// Reset every zone on the drive. Addresses no single zone.
    ResetAll,
}

/// A drive's whole zone report.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ZoneReport {
    /// The zone size the drive states, in its own blocks. Uniform across the
    /// drive; a zone's own length may still be shorter at the last zone.
    pub zone_blocks: u64,
    /// The most zones the drive keeps open at once, when it states a limit.
    pub max_open_zones: Option<u32>,
    /// The most zones the drive keeps active at once, when it states a limit.
    /// A zone is active while it holds a partial write; the limit is usually
    /// the tighter of the two and is the one a writer runs into first.
    pub max_active_zones: Option<u32>,
    /// The largest single zone-append the drive accepts, in its own blocks.
    /// `None` when the drive supports no append at all.
    pub max_append_blocks: Option<u64>,
    pub zones: Vec<Zone>,
}

#[cfg(test)]
#[path = "zoned/tests.rs"]
mod tests;
