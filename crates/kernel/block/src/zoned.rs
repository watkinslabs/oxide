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

/// One zone, in units of the device's own block size.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Zone {
    pub start_block: u64,
    pub len_blocks: u64,
    /// Blocks of `len_blocks` that may hold data. Equal to the length on a
    /// zone with no short capacity.
    pub capacity_blocks: u64,
    pub kind: ZoneType,
}

/// A drive's whole zone report.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ZoneReport {
    /// The zone size the drive states, in its own blocks. Uniform across the
    /// drive; a zone's own length may still be shorter at the last zone.
    pub zone_blocks: u64,
    /// The most zones the drive keeps open at once, when it states a limit.
    pub max_open_zones: Option<u32>,
    pub zones: Vec<Zone>,
}
