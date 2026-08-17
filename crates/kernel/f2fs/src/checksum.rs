//! The one checksum this filesystem uses, and the four things it seals.
//!
//! It is the reflected CRC-32 of Ethernet and zlib, but **without** the
//! pre-inversion and post-inversion those conventions apply, and seeded with
//! the volume magic rather than with all-ones. Feeding the same bytes to a
//! standard `crc32()` gives a different answer, so a checker written against
//! the usual convention rejects every valid volume and accepts none.
//!
//! Chaining is the other half of the contract: the inode checksum runs four
//! separate passes whose output seeds the next, so the pieces cannot be
//! concatenated and hashed in one go.

use crate::uapi;

/// The seed a fresh volume checksum starts from.
pub const SEED: u32 = uapi::MAGIC;

/// Continue a checksum over `bytes`. # C: O(N)
pub fn chksum(seed: u32, bytes: &[u8]) -> u32 { crc::crc32_update(seed, bytes) }

/// A fresh checksum over `bytes`. # C: O(N)
pub fn crc32(bytes: &[u8]) -> u32 { chksum(SEED, bytes) }

/// Whether a superblock copy's stored CRC matches its bytes.
///
/// The range is everything ahead of the CRC word, which is why the stored
/// `checksum_offset` has to equal the CRC's own position before the sum is
/// worth computing: a volume naming any other offset would have us checksum a
/// range nobody sealed.
/// # C: O(SUPER_SIZE)
pub fn super_ok(sb: &[u8]) -> bool {
    let Some(off) = uapi::le32(sb, uapi::SB_CHECKSUM_OFFSET) else { return false };
    if off as usize != uapi::SB_CRC { return false; }
    let Some(stored) = uapi::le32(sb, uapi::SB_CRC) else { return false };
    let Some(body) = sb.get(..uapi::SB_CRC) else { return false };
    stored == crc32(body)
}

/// Whether a checkpoint block's CRC matches, given the offset it names.
///
/// The offset is not fixed: it moves with the two version bitmaps, so it is
/// read from the block and bounded before it is used. Both bounds matter — an
/// offset below the bitmaps would leave the bitmaps unsealed, and one past the
/// block's last word would read off the end.
/// # C: O(crc_offset)
pub fn checkpoint_ok(cp: &[u8]) -> bool {
    let Some(off) = crc_offset(cp) else { return false };
    let Some(stored) = uapi::le32(cp, off) else { return false };
    let Some(body) = cp.get(..off) else { return false };
    stored == crc32(body)
}

/// Where a checkpoint block's CRC sits, or `None` when the block names an
/// offset outside the range the format allows. # C: O(1)
pub fn crc_offset(cp: &[u8]) -> Option<usize> {
    let off = uapi::le32(cp, uapi::CP_CHECKSUM_OFFSET_FIELD)? as usize;
    if off < uapi::CP_SIT_NAT_VERSION_BITMAP || off > uapi::CP_MAX_CHKSUM_OFFSET { return None; }
    Some(off)
}

/// The per-volume seed every inode checksum starts from, derived from the
/// volume's uuid. # C: O(1)
pub fn inode_seed(uuid: &[u8]) -> u32 { chksum(u32::MAX, uuid) }

/// The checksum a node block holding an inode should carry.
///
/// Four passes, each seeded by the last: the footer's inode number, then the
/// generation, then the inode up to the checksum word, then a zeroed stand-in
/// for that word, then the rest of the block. The stand-in is what lets the
/// stored value be excluded without moving any bytes.
/// # C: O(BLKSIZE)
pub fn inode_chksum(seed: u32, block: &[u8]) -> Option<u32> {
    let ino = block.get(uapi::NODE_FOOTER_OFF + uapi::FOOTER_INO..)?.get(..4)?;
    let gen = block.get(uapi::I_GENERATION..)?.get(..4)?;
    let cs = uapi::I_INODE_CHECKSUM;
    let mut c = chksum(seed, ino);
    c = chksum(c, gen);
    c = chksum(c, block.get(..cs)?);
    c = chksum(c, &[0u8; 4]);
    // The node FOOTER is outside what an inode's checksum covers, which is
    // what lets the footer be finished after the inode is sealed: the
    // checkpoint version and the forward pointer are stamped when the block is
    // placed, long after its contents were settled. Covering them would make
    // every deferred inode fail its own checksum, and would disagree with the
    // on-disk value any other implementation computes.
    Some(chksum(c, block.get(cs + 4..uapi::NODE_FOOTER_OFF)?))
}

#[cfg(test)]
#[path = "tests/checksum.rs"]
mod tests;
