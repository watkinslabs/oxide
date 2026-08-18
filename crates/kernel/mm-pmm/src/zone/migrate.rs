//! Mobility classes carried independently from the zone selector.

use super::gfp::{GFP_MOVABLE, GFP_RECLAIMABLE, GfpError};

/// Pageblock size used for mobility grouping. A 2 MiB block keeps the type
/// map small while matching the base huge-page granularity on both targets.
pub const PAGEBLOCK_ORDER: u8 = 9;
/// Base pages in one mobility pageblock.
pub const PAGEBLOCK_PAGES: u64 = 1u64 << PAGEBLOCK_ORDER;
/// Number of mobility classes that participate in allocation and PCP lists.
pub const MIGRATE_TYPES: usize = 3;

/// Placement class of free memory and the allocations it serves.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MigrateType { Unmovable = 0, Movable = 1, Reclaimable = 2 }

impl MigrateType {
    /// Index into per-migratetype free-list tables. # C: O(1)
    pub const fn index(self) -> usize { self as usize }

    /// Ordered fallback types. # C: O(1)
    pub const fn fallbacks(self) -> [Self; MIGRATE_TYPES - 1] {
        match self {
            Self::Unmovable => [Self::Reclaimable, Self::Movable],
            Self::Movable => [Self::Reclaimable, Self::Unmovable],
            Self::Reclaimable => [Self::Unmovable, Self::Movable],
        }
    }

    /// Convert a compact stored type to its enum. # C: O(1)
    pub const fn from_index(index: usize) -> Self {
        match index { 1 => Self::Movable, 2 => Self::Reclaimable, _ => Self::Unmovable }
    }
}

/// Derive an allocation's mobility class. The two mobility bits are mutually
/// exclusive; a caller setting both has not named a usable allocation class.
/// # C: O(1)
pub const fn gfp_migratetype(flags: u32) -> Result<MigrateType, GfpError> {
    match flags & (GFP_MOVABLE | GFP_RECLAIMABLE) {
        0 => Ok(MigrateType::Unmovable),
        GFP_MOVABLE => Ok(MigrateType::Movable),
        GFP_RECLAIMABLE => Ok(MigrateType::Reclaimable),
        _ => Err(GfpError),
    }
}
