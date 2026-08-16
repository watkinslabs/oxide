//! One superblock copy's bytes into its fields.
//!
//! Nothing here judges the values — a copy that parses may still be nonsense,
//! and `sanity` is where that is decided. Parsing fails only when the slice is
//! too short to hold a superblock at all, which is the one thing that would
//! make every field a guess.

use alloc::string::String;
use alloc::vec::Vec;

use crate::uapi::*;

use super::SuperBlock;

/// Read a copy. `sb` is the copy's own bytes, from its magic onward.
/// # C: O(SUPER_SIZE)
pub fn parse(sb: &[u8]) -> Option<SuperBlock> {
    if sb.len() < SUPER_SIZE { return None; }
    if le32(sb, SB_MAGIC)? != MAGIC { return None; }
    let mut uuid = [0u8; SB_UUID_LEN];
    uuid.copy_from_slice(sb.get(SB_UUID..SB_UUID + SB_UUID_LEN)?);
    let mut qf_ino = [0u32; MAX_QUOTAS];
    for (i, slot) in qf_ino.iter_mut().enumerate() { *slot = le32(sb, SB_QF_INO + i * 4)?; }
    Some(SuperBlock {
        major_ver: le16(sb, SB_MAJOR_VER)?,
        minor_ver: le16(sb, SB_MINOR_VER)?,
        log_sectorsize: le32(sb, SB_LOG_SECTORSIZE)?,
        log_sectors_per_block: le32(sb, SB_LOG_SECTORS_PER_BLOCK)?,
        log_blocksize: le32(sb, SB_LOG_BLOCKSIZE)?,
        log_blocks_per_seg: le32(sb, SB_LOG_BLOCKS_PER_SEG)?,
        segs_per_sec: le32(sb, SB_SEGS_PER_SEC)?,
        secs_per_zone: le32(sb, SB_SECS_PER_ZONE)?,
        checksum_offset: le32(sb, SB_CHECKSUM_OFFSET)?,
        block_count: le64(sb, SB_BLOCK_COUNT)?,
        section_count: le32(sb, SB_SECTION_COUNT)?,
        segment_count: le32(sb, SB_SEGMENT_COUNT)?,
        segment_count_ckpt: le32(sb, SB_SEGMENT_COUNT_CKPT)?,
        segment_count_sit: le32(sb, SB_SEGMENT_COUNT_SIT)?,
        segment_count_nat: le32(sb, SB_SEGMENT_COUNT_NAT)?,
        segment_count_ssa: le32(sb, SB_SEGMENT_COUNT_SSA)?,
        segment_count_main: le32(sb, SB_SEGMENT_COUNT_MAIN)?,
        segment0_blkaddr: le32(sb, SB_SEGMENT0_BLKADDR)?,
        cp_blkaddr: le32(sb, SB_CP_BLKADDR)?,
        sit_blkaddr: le32(sb, SB_SIT_BLKADDR)?,
        nat_blkaddr: le32(sb, SB_NAT_BLKADDR)?,
        ssa_blkaddr: le32(sb, SB_SSA_BLKADDR)?,
        main_blkaddr: le32(sb, SB_MAIN_BLKADDR)?,
        root_ino: le32(sb, SB_ROOT_INO)?,
        node_ino: le32(sb, SB_NODE_INO)?,
        meta_ino: le32(sb, SB_META_INO)?,
        uuid,
        volume_name: volume_name(sb)?,
        extension_count: le32(sb, SB_EXTENSION_COUNT)?,
        extensions: extensions(sb)?,
        hot_ext_count: *sb.get(SB_HOT_EXT_COUNT)?,
        cp_payload: le32(sb, SB_CP_PAYLOAD)?,
        feature: le32(sb, SB_FEATURE)?,
        s_encoding: le16(sb, SB_S_ENCODING)?,
        s_encoding_flags: le16(sb, SB_S_ENCODING_FLAGS)?,
        device_segments: device_segments(sb)?,
        qf_ino,
        crc: le32(sb, SB_CRC)?,
    })
}

/// The label, which is UTF-16 on the medium and stops at its first zero unit.
///
/// An unpaired surrogate is replaced rather than refused: the label is
/// presentation, and a volume is not unmountable because someone gave it a
/// name no encoder should have produced.
/// # C: O(SB_VOLUME_NAME_UNITS)
fn volume_name(sb: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for i in 0..SB_VOLUME_NAME_UNITS {
        let u = le16(sb, SB_VOLUME_NAME + i * 2)?;
        if u == 0 { break; }
        units.push(u);
    }
    Some(char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect())
}

/// The extension list, trimmed at each entry's first zero byte.
///
/// The stored count is not trusted to bound the read: it is checked in
/// `sanity`, and a copy that fails that check must still have parsed without
/// running off the array.
/// # C: O(MAX_EXTENSION * EXTENSION_LEN)
fn extensions(sb: &[u8]) -> Option<Vec<String>> {
    let count = (le32(sb, SB_EXTENSION_COUNT)? as usize).min(MAX_EXTENSION as usize);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = SB_EXTENSION_LIST + i * EXTENSION_LEN;
        let raw = sb.get(at..at + EXTENSION_LEN)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(EXTENSION_LEN);
        out.push(String::from_utf8_lossy(&raw[..end]).into_owned());
    }
    Some(out)
}

/// Segments each listed device contributes.
///
/// The list ends at the first entry with an empty path, and an empty list
/// means the volume is the one device it was mounted from.
/// # C: O(MAX_DEVICES)
fn device_segments(sb: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for i in 0..MAX_DEVICES {
        let at = SB_DEVS + i * DEV_ENTRY_SIZE;
        if *sb.get(at)? == 0 { break; }
        out.push(le32(sb, at + DEV_PATH_LEN)?);
    }
    Some(out)
}

#[cfg(test)]
#[path = "../tests/sb_parse.rs"]
mod tests;
