//! Allocation-flag zone selection. The four low flag bits name the highest
//! zone an allocation may use; everything at or below that index is reachable
//! through the fallback walk, and everything above it is not.
//!
//! Only one of DMA / HIGHMEM / DMA32 may be set. `MOVABLE` is both a zone
//! selector and a placement policy, so it composes with exactly one of the
//! other three. Every other combination is rejected rather than silently
//! resolved: a caller that asks for two mutually exclusive bounds has a bug,
//! and picking one of them for it is how a device gets an address it cannot
//! reach.

use super::types::ZoneType;

/// Allocation must be addressable by the narrowest bus masters.
pub const GFP_DMA: u32 = 0x01;
/// No separate high-memory zone exists on a 64-bit direct map; the bit is part
/// of the zone mask because it composes with `GFP_MOVABLE`.
pub const GFP_HIGHMEM: u32 = 0x02;
/// Allocation must be addressable with 32 physical address bits.
pub const GFP_DMA32: u32 = 0x04;
/// Allocation holds migratable content and may be placed in the movable zone.
pub const GFP_MOVABLE: u32 = 0x08;
/// The flag bits that participate in zone selection.
pub const GFP_ZONEMASK: u32 = GFP_DMA | GFP_HIGHMEM | GFP_DMA32 | GFP_MOVABLE;

/// Caller is high-priority and may be served from half the min reserve. This
/// is the ONLY flag that opens the reserve; a caller that merely cannot block
/// is held to the full minimum.
pub const GFP_HIGH: u32 = 0x20;
/// Caller may wake background reclaim but never blocks on it.
pub const GFP_KSWAPD_RECLAIM: u32 = 0x800;
/// The interrupt-context allocation: reserve access without blocking.
pub const GFP_ATOMIC: u32 = GFP_HIGH | GFP_KSWAPD_RECLAIM;

/// Does `flags` earn the reserve discount? # C: O(1)
pub const fn grants_min_reserve(flags: u32) -> bool { flags & GFP_HIGH != 0 }

/// A flag combination that names no zone.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GfpError;

/// Highest zone `flags` permits, or `GfpError` for a contradictory request.
/// # C: O(1)
pub const fn gfp_zone(flags: u32) -> Result<ZoneType, GfpError> {
    match flags & GFP_ZONEMASK {
        0x0 => Ok(ZoneType::Normal),
        0x1 => Ok(ZoneType::Dma),
        0x2 => Ok(ZoneType::Normal),
        0x4 => Ok(ZoneType::Dma32),
        0x8 => Ok(ZoneType::Normal),
        0x9 => Ok(ZoneType::Dma),
        0xa => Ok(ZoneType::Movable),
        0xc => Ok(ZoneType::Dma32),
        _ => Err(GfpError),
    }
}
