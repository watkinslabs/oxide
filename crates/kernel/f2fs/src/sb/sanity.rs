//! Whether a parsed superblock can describe a real volume.
//!
//! The area cross-checks are the load-bearing half. Each area's start must be
//! exactly the previous area's start plus that area's segment count in blocks,
//! so the six addresses and the five counts are one over-determined system:
//! a single wrong field breaks the chain and is caught here rather than by a
//! read landing in the wrong area, which produces plausible garbage instead of
//! an error.

use crate::checksum;
use crate::features;
use crate::flags::FEATURE_SB_CHKSUM;
use crate::limits::*;
use crate::uapi;

use super::SuperBlock;

/// Why a superblock copy was rejected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SbError {
    /// The stored CRC does not match the bytes it seals.
    Checksum,
    /// The block size is not the one this build reads.
    BlockSize,
    /// Segments are not the size the format fixes them at.
    SegmentSize,
    /// The sector size, or its relation to the block size, is impossible.
    SectorSize,
    /// A count is zero, absurd, or disagrees with another count.
    Counts,
    /// The volume states more segments than it has blocks for.
    Blocks,
    /// The extension list overruns the array that holds it.
    Extensions,
    /// The checkpoint payload leaves no room for the pack itself.
    CpPayload,
    /// The three reserved inode numbers are not the fixed ones.
    ReservedIno,
    /// Two areas do not meet where their segment counts say they must.
    AreaBoundary,
}

/// Check one copy. `raw` is that copy's bytes, needed for the CRC.
///
/// The CRC is checked only when the volume claims to maintain one: a volume
/// formatted before the feature existed carries a zero there, and refusing it
/// would refuse every older volume.
/// # C: O(SUPER_SIZE)
pub fn check(sb: &SuperBlock, raw: &[u8]) -> Result<(), SbError> {
    if sb.feature & FEATURE_SB_CHKSUM != 0 && !checksum::super_ok(raw) {
        return Err(SbError::Checksum);
    }
    if sb.log_blocksize != uapi::BLKSIZE_BITS { return Err(SbError::BlockSize); }
    if sb.log_blocks_per_seg != uapi::LOG_BLKS_PER_SEG { return Err(SbError::SegmentSize); }
    if sb.log_sectorsize > MAX_LOG_SECTOR_SIZE || sb.log_sectorsize < MIN_LOG_SECTOR_SIZE {
        return Err(SbError::SectorSize);
    }
    if sb.log_sectors_per_block + sb.log_sectorsize != MAX_LOG_SECTOR_SIZE {
        return Err(SbError::SectorSize);
    }
    counts(sb)?;
    if sb.extension_count > uapi::MAX_EXTENSION
        || u32::from(sb.hot_ext_count) > uapi::MAX_EXTENSION
        || sb.extension_count + u32::from(sb.hot_ext_count) > uapi::MAX_EXTENSION
    {
        return Err(SbError::Extensions);
    }
    // The pack needs its own two blocks and one summary block per persistent
    // log; a payload that eats those leaves the pack unreadable.
    let room = sb.blks_per_seg() - uapi::CP_PACKS - uapi::NR_CURSEG_PERSIST_TYPE as u32;
    if sb.cp_payload >= room { return Err(SbError::CpPayload); }
    if sb.node_ino != 1 || sb.meta_ino != 2 || sb.root_ino != 3 {
        return Err(SbError::ReservedIno);
    }
    areas(sb)
}

/// The segment and section counts, and how they multiply. # C: O(1)
fn counts(sb: &SuperBlock) -> Result<(), SbError> {
    if sb.segment_count > MAX_SEGMENT || sb.segment_count < MIN_SEGMENTS {
        return Err(SbError::Counts);
    }
    if sb.section_count > sb.segment_count_main
        || sb.section_count < 1
        || sb.segs_per_sec > sb.segment_count
        || sb.segs_per_sec == 0
    {
        return Err(SbError::Counts);
    }
    if sb.segment_count_main != sb.section_count.saturating_mul(sb.segs_per_sec) {
        return Err(SbError::Counts);
    }
    if (sb.segment_count / sb.segs_per_sec) < sb.section_count { return Err(SbError::Counts); }
    // Nine blocks per sector-of-512 is the format's own ratio between a
    // segment and the user block count it is expressed against.
    if u64::from(sb.segment_count) > (sb.block_count >> 9) { return Err(SbError::Blocks); }
    if sb.secs_per_zone > sb.section_count || sb.secs_per_zone == 0 {
        return Err(SbError::Counts);
    }
    if !sb.devices.is_empty() {
        let total: u64 = sb.devices.iter().map(|d| u64::from(d.total_segments)).sum();
        if total != u64::from(sb.segment_count) { return Err(SbError::Counts); }
    }
    Ok(())
}

/// The five areas, each of which must end exactly where the next begins.
/// # C: O(1)
fn areas(sb: &SuperBlock) -> Result<(), SbError> {
    let shift = sb.log_blocks_per_seg;
    let after = |start: u32, segs: u32| u64::from(start) + (u64::from(segs) << shift);
    if sb.segment0_blkaddr != sb.cp_blkaddr { return Err(SbError::AreaBoundary); }
    if after(sb.cp_blkaddr, sb.segment_count_ckpt) != u64::from(sb.sit_blkaddr) {
        return Err(SbError::AreaBoundary);
    }
    if after(sb.sit_blkaddr, sb.segment_count_sit) != u64::from(sb.nat_blkaddr) {
        return Err(SbError::AreaBoundary);
    }
    if after(sb.nat_blkaddr, sb.segment_count_nat) != u64::from(sb.ssa_blkaddr) {
        return Err(SbError::AreaBoundary);
    }
    if after(sb.ssa_blkaddr, sb.segment_count_ssa) != u64::from(sb.main_blkaddr) {
        return Err(SbError::AreaBoundary);
    }
    // The main area may stop short of the volume's end — a formatter that
    // rounded down leaves the tail unused — but it may never run past it.
    if after(sb.main_blkaddr, sb.segment_count_main) > sb.max_blkaddr() {
        return Err(SbError::AreaBoundary);
    }
    Ok(())
}

/// What this mount may do with the volume, or why it may not.
/// # C: O(1)
#[inline(never)]
pub fn access(sb: &SuperBlock) -> Result<features::Access, features::Refusal> {
    // A folding volume is mountable exactly when its encoding is one this
    // build can load: the table is what every lookup resolves through, and
    // guessing at an encoding we do not have would report names absent that
    // the directory would match.
    if features::has_casefold(sb.feature)
        && crate::casefold::Casefold::load(sb.s_encoding, sb.s_encoding_flags).is_err()
    {
        return Err(features::Refusal::Casefold);
    }
    features::access(sb.feature)
}

#[cfg(test)]
#[path = "../tests/sb_sanity.rs"]
mod tests;
