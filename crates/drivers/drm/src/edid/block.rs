//! Base-block validity: header, checksum, version, preferred-timing policy.

use super::layout::*;

/// Bytes of the base block, or `None` when the buffer is shorter than one
/// block. Extension blocks past the first are not consumed here. # C: O(1)
pub fn base_block(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < BLOCK_LEN { None } else { Some(&bytes[..BLOCK_LEN]) }
}

/// How many of the 8 header bytes match the fixed opening pattern. A perfect
/// base block scores 8; a blob that is not EDID at all scores near 0.
/// # C: O(1)
pub fn header_score(block: &[u8]) -> u32 {
    let mut score = 0;
    for (i, want) in HEADER.iter().enumerate() {
        if block.get(OFF_HEADER + i) == Some(want) { score += 1; }
    }
    score
}

/// Header matches the fixed opening pattern exactly. # C: O(1)
pub fn header_is_valid(block: &[u8]) -> bool {
    header_score(block) == HEADER.len() as u32
}

/// Checksum byte that makes the block's bytes sum to zero modulo 256.
/// # C: O(BLOCK_LEN)
pub fn computed_checksum(block: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for b in block.iter().take(OFF_CHECKSUM) { sum = sum.wrapping_add(*b); }
    sum.wrapping_neg()
}

/// Stored checksum agrees with the block's contents. # C: O(BLOCK_LEN)
pub fn checksum_is_valid(block: &[u8]) -> bool {
    block.len() >= BLOCK_LEN && computed_checksum(block) == block[OFF_CHECKSUM]
}

/// A blob usable as an EDID base block: full length, exact header, and a
/// checksum that agrees. A blob failing any of these is not published — a
/// compositor reading a corrupt EDID picks a mode the display cannot show.
/// # C: O(BLOCK_LEN)
pub fn is_valid(bytes: &[u8]) -> bool {
    match base_block(bytes) {
        Some(block) => header_is_valid(block) && checksum_is_valid(block),
        None => false,
    }
}

/// EDID structure revision (the minor half of the version pair). # C: O(1)
pub fn revision(block: &[u8]) -> u8 { block.get(OFF_REVISION).copied().unwrap_or(0) }

/// EDID structure version (the major half). # C: O(1)
pub fn version(block: &[u8]) -> u8 { block.get(OFF_VERSION).copied().unwrap_or(0) }

/// Whether the first detailed descriptor is the display's preferred timing.
/// Revision 4 and later always place it there; earlier revisions say so with
/// the feature byte's preferred-timing bit. # C: O(1)
pub fn first_detailed_is_preferred(block: &[u8]) -> bool {
    if revision(block) >= REVISION_PREFERRED_ALWAYS { return true; }
    block.get(OFF_FEATURES).copied().unwrap_or(0) & FEATURE_PREFERRED_TIMING != 0
}

/// The `idx`-th 18-byte descriptor of the base block. # C: O(1)
pub fn descriptor(block: &[u8], idx: usize) -> Option<&[u8]> {
    if idx >= DTD_COUNT { return None; }
    let at = OFF_DETAILED + idx * DTD_LEN;
    block.get(at..at + DTD_LEN)
}
