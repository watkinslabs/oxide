// Frame and block headers (RFC 8878 3.1.1.1, 3.1.1.2).

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::{BLOCK_HEADER_LEN, BLOCK_LAST_MASK, BLOCK_SIZE_MAX, BLOCK_SIZE_SHIFT,
    BLOCK_TYPE_COMPRESSED, BLOCK_TYPE_MASK, BLOCK_TYPE_RAW, BLOCK_TYPE_RESERVED, BLOCK_TYPE_RLE,
    BLOCK_TYPE_SHIFT, FHD_CONTENT_CHECKSUM, FHD_DICTIONARY_ID_MASK, FHD_FRAME_CONTENT_SIZE_SHIFT,
    FHD_RESERVED, FHD_SINGLE_SEGMENT, MAGIC, WINDOW_EXPONENT_SHIFT, WINDOW_LOG_MAX,
    WINDOW_LOG_MIN, WINDOW_MANTISSA_MASK};
use crate::{Error, Result};

#[derive(Debug)]
pub struct Header {
    /// Declared decompressed size, when the frame states one.
    pub content_size: Option<u64>,
    /// Dictionary the frame requires, or 0 for none. A raw-content dictionary
    /// is invisible here, so 0 does not prove no dictionary is needed.
    pub dict_id: u32,
    pub window_size: u64,
    pub has_checksum: bool,
    /// Bytes the header occupied, magic included.
    pub len: usize,
}

/// Parse a frame header.
/// # C: O(1)
pub fn read_header(src: &[u8]) -> Result<Header> {
    const MAGIC_LEN: usize = 4;
    if src.len() < MAGIC_LEN + 1 { return Err(Error::Truncated); }
    let magic = u32::from_le_bytes(src[..MAGIC_LEN].try_into().expect("four bytes"));
    if magic != MAGIC { return Err(Error::BadMagic); }
    let fhd = src[MAGIC_LEN];
    if fhd & FHD_RESERVED != 0 { return Err(Error::BadFrameHeader); }
    let single_segment = fhd & FHD_SINGLE_SEGMENT != 0;
    let dict_id_len = match fhd & FHD_DICTIONARY_ID_MASK {
        0 => 0usize,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    // The content-size field is 0 bytes only when the frame is multi-segment;
    // a single-segment frame always states its size, because it has no window
    // descriptor to bound the buffer instead.
    let fcs_code = fhd >> FHD_FRAME_CONTENT_SIZE_SHIFT;
    let fcs_len = match fcs_code {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };

    let mut at = MAGIC_LEN + 1;
    let window_size = if single_segment {
        // No window descriptor: the window is exactly the content.
        0
    } else {
        let Some(&wd) = src.get(at) else { return Err(Error::Truncated) };
        at += 1;
        let exponent = (wd >> WINDOW_EXPONENT_SHIFT) as u32 + WINDOW_LOG_MIN;
        if exponent > WINDOW_LOG_MAX { return Err(Error::WindowTooLarge); }
        let mantissa = (wd & WINDOW_MANTISSA_MASK) as u64;
        let base = 1u64 << exponent;
        base + (base / 8) * mantissa
    };

    if src.len() < at + dict_id_len + fcs_len { return Err(Error::Truncated); }
    let mut dict_id = 0u32;
    if dict_id_len != 0 {
        for i in 0..dict_id_len { dict_id |= (src[at + i] as u32) << (8 * i); }
        at += dict_id_len;
    }
    let content_size = if fcs_len == 0 { None } else {
        let mut v = 0u64;
        for i in 0..fcs_len { v |= (src[at + i] as u64) << (8 * i); }
        at += fcs_len;
        // The 2-byte form is biased by 256: it covers 256..=65791, because
        // anything smaller fits the 1-byte form.
        Some(if fcs_len == 2 { v + 256 } else { v })
    };
    let window_size = if single_segment { content_size.unwrap_or(0) } else { window_size };
    Ok(Header {
        content_size,
        dict_id,
        window_size,
        has_checksum: fhd & FHD_CONTENT_CHECKSUM != 0,
        len: at,
    })
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BlockKind { Raw, Rle, Compressed }

#[derive(Debug)]
pub struct BlockHeader {
    pub last: bool,
    pub kind: BlockKind,
    /// Bytes of block payload following the header. For an RLE block this is
    /// the REPEAT COUNT, not a byte count -- the payload is a single byte.
    pub size: usize,
}

/// Parse a 3-byte block header.
/// # C: O(1)
pub fn read_block_header(src: &[u8]) -> Result<BlockHeader> {
    if src.len() < BLOCK_HEADER_LEN { return Err(Error::Truncated); }
    let v = src[0] as u32 | ((src[1] as u32) << 8) | ((src[2] as u32) << 16);
    let kind = match (v >> BLOCK_TYPE_SHIFT) & BLOCK_TYPE_MASK {
        BLOCK_TYPE_RAW => BlockKind::Raw,
        BLOCK_TYPE_RLE => BlockKind::Rle,
        BLOCK_TYPE_COMPRESSED => BlockKind::Compressed,
        BLOCK_TYPE_RESERVED => return Err(Error::ReservedBlockType),
        _ => unreachable!("two-bit field"),
    };
    let size = (v >> BLOCK_SIZE_SHIFT) as usize;
    if size > BLOCK_SIZE_MAX { return Err(Error::BlockTooLarge); }
    Ok(BlockHeader { last: v & BLOCK_LAST_MASK != 0, kind, size })
}

/// Emit a frame header for a single-segment frame of known size.
///
/// Single-segment is the right shape for zram: one page in, one frame out, no
/// window to describe and no back-references across frames.
/// # C: O(1)
pub fn write_header(content_size: u64, checksum: bool, dict_id: u32, out: &mut Vec<u8>) {
    const FCS_1BYTE_MAX: u64 = 255;
    const FCS_2BYTE_BIAS: u64 = 256;
    const FCS_2BYTE_MAX: u64 = 65535 + FCS_2BYTE_BIAS;
    const FCS_4BYTE_MAX: u64 = u32::MAX as u64;
    out.extend_from_slice(&MAGIC.to_le_bytes());
    let (fcs_code, fcs_len) = if content_size <= FCS_1BYTE_MAX { (0u8, 1usize) }
        else if content_size <= FCS_2BYTE_MAX { (1, 2) }
        else if content_size <= FCS_4BYTE_MAX { (2, 4) }
        else { (3, 8) };
    // Dictionary_ID uses the narrowest field that holds it, and is omitted
    // entirely for a raw-content dictionary, which has no id to name.
    let did_len = if dict_id == 0 { 0usize }
        else if dict_id <= u8::MAX as u32 { 1 }
        else if dict_id <= u16::MAX as u32 { 2 }
        else { 4 };
    let did_code = match did_len { 0 => 0u8, 1 => 1, 2 => 2, _ => 3 };
    let mut fhd = FHD_SINGLE_SEGMENT | (fcs_code << FHD_FRAME_CONTENT_SIZE_SHIFT) | did_code;
    if checksum { fhd |= FHD_CONTENT_CHECKSUM; }
    out.push(fhd);
    out.extend_from_slice(&dict_id.to_le_bytes()[..did_len]);
    let stored = if fcs_len == 2 { content_size - FCS_2BYTE_BIAS } else { content_size };
    out.extend_from_slice(&stored.to_le_bytes()[..fcs_len]);
}

/// Emit a block header. `size` is the payload length, or the repeat count for
/// an RLE block.
/// # C: O(1)
pub fn write_block_header(last: bool, kind: BlockKind, size: usize, out: &mut Vec<u8>) {
    let type_bits = match kind {
        BlockKind::Raw => BLOCK_TYPE_RAW,
        BlockKind::Rle => BLOCK_TYPE_RLE,
        BlockKind::Compressed => BLOCK_TYPE_COMPRESSED,
    };
    let v = u32::from(last) | (type_bits << BLOCK_TYPE_SHIFT) | ((size as u32) << BLOCK_SIZE_SHIFT);
    out.extend_from_slice(&v.to_le_bytes()[..BLOCK_HEADER_LEN]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_content_size_width_round_trips() {
        // The 2-byte form's 256 bias is the trap here: a frame of exactly 256
        // bytes stores 0, and reading it without the bias yields 0 instead.
        for size in [0u64, 1, 255, 256, 257, 65791, 65792, 100_000, 5_000_000_000] {
            let mut buf = alloc::vec::Vec::new();
            write_header(size, false, 0, &mut buf);
            let h = read_header(&buf).expect("our own header parses");
            assert_eq!(h.content_size, Some(size), "size {size}");
            assert_eq!(h.len, buf.len());
            assert!(!h.has_checksum);
        }
    }

    #[test]
    fn the_checksum_flag_survives_the_round_trip() {
        let mut buf = alloc::vec::Vec::new();
        write_header(4096, true, 0, &mut buf);
        assert!(read_header(&buf).unwrap().has_checksum);
    }

    #[test]
    fn a_foreign_magic_is_refused_before_anything_else_is_read() {
        assert_eq!(read_header(&[0, 0, 0, 0, 0]).unwrap_err(), Error::BadMagic);
        assert_eq!(read_header(&[0x28]).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn every_dictionary_id_width_round_trips() {
        // The width is chosen by magnitude, so each boundary shifts every
        // field that follows if it is read back wrong.
        for id in [0u32, 1, 255, 256, 65535, 65536, 0xDEAD_BEEF] {
            let mut buf = alloc::vec::Vec::new();
            write_header(4096, false, id, &mut buf);
            let h = read_header(&buf).expect("our own header parses");
            assert_eq!(h.dict_id, id, "id {id}");
            assert_eq!(h.content_size, Some(4096));
            assert_eq!(h.len, buf.len());
        }
    }

    #[test]
    fn an_oversized_window_is_refused_rather_than_allocated() {
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.push(0);
        buf.push(0xFF);
        assert_eq!(read_header(&buf).unwrap_err(), Error::WindowTooLarge);
    }

    #[test]
    fn block_headers_round_trip_and_reject_the_reserved_type() {
        for (last, kind, size) in [(true, BlockKind::Raw, 0usize),
            (false, BlockKind::Rle, 4096), (true, BlockKind::Compressed, 131_072)]
        {
            let mut buf = alloc::vec::Vec::new();
            write_block_header(last, kind, size, &mut buf);
            let h = read_block_header(&buf).unwrap();
            assert_eq!((h.last, h.kind, h.size), (last, kind, size));
        }
        assert_eq!(read_block_header(&[0b110, 0, 0]).unwrap_err(), Error::ReservedBlockType);
        assert_eq!(read_block_header(&[0, 0]).unwrap_err(), Error::Truncated);
    }
}
