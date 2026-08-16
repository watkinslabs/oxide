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

/// One zone, in the volume's block unit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Zone {
    pub start_blk: u64,
    pub len_blks: u32,
    /// Blocks of `len_blks` that may be written. Equal to the length on a
    /// zone that has no short capacity.
    pub cap_blks: u32,
    pub kind: ZoneType,
}

impl Zone {
    /// Blocks inside this zone that can never hold data. # C: O(1)
    pub fn unusable_blks(&self) -> u32 { self.len_blks.saturating_sub(self.cap_blks) }
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
