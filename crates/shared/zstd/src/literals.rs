// Literals section (RFC 8878 3.1.1.3.1).
//
// Four forms. Raw copies bytes straight through, RLE repeats one byte, and the
// two Huffman forms differ only in whether the block carries its own weight
// table or reuses the previous block's — which is why the table is threaded
// through as an `Option` the caller owns across blocks.

extern crate alloc;
use alloc::vec::Vec;

use crate::huff;
use crate::uapi::{LITERALS_MAX, LITERALS_SIZE_FORMAT_MASK, LITERALS_SIZE_FORMAT_SHIFT,
    LITERALS_TYPE_HUFFMAN, LITERALS_TYPE_HUFFMAN_REUSE, LITERALS_TYPE_MASK, LITERALS_TYPE_RAW,
    LITERALS_TYPE_RLE};
use crate::{Error, Result};

/// Decode the literals section. Appends to `out` and returns the bytes the
/// section occupied.
///
/// `table` carries the Huffman table ACROSS blocks: a block may state that it
/// reuses the previous block's table, so this both reads and replaces it.
/// # C: O(literals)
pub fn decode(src: &[u8], out: &mut Vec<u8>, table: &mut Option<huff::Table>) -> Result<usize> {
    let Some(&header) = src.first() else { return Err(Error::Truncated) };
    let kind = header & LITERALS_TYPE_MASK;
    let size_format = (header >> LITERALS_SIZE_FORMAT_SHIFT) & LITERALS_SIZE_FORMAT_MASK;

    match kind {
        LITERALS_TYPE_RAW | LITERALS_TYPE_RLE => {
            let (regenerated, header_len) = match size_format {
                // Size formats 0 and 2 both mean "5-bit size in this byte";
                // only bit 2 of the format field is meaningful here.
                0 | 2 => ((header >> 3) as usize, 1),
                1 => {
                    if src.len() < 2 { return Err(Error::Truncated); }
                    (((header >> 4) as usize) | ((src[1] as usize) << 4), 2)
                }
                _ => {
                    if src.len() < 3 { return Err(Error::Truncated); }
                    (((header >> 4) as usize) | ((src[1] as usize) << 4)
                        | ((src[2] as usize) << 12), 3)
                }
            };
            if regenerated > LITERALS_MAX { return Err(Error::BlockTooLarge); }
            if kind == LITERALS_TYPE_RAW {
                let end = header_len + regenerated;
                if src.len() < end { return Err(Error::Truncated); }
                out.extend_from_slice(&src[header_len..end]);
                Ok(end)
            } else {
                let Some(&byte) = src.get(header_len) else { return Err(Error::Truncated) };
                out.resize(out.len() + regenerated, byte);
                Ok(header_len + 1)
            }
        }
        LITERALS_TYPE_HUFFMAN | LITERALS_TYPE_HUFFMAN_REUSE => {
            let (regenerated, compressed, header_len, four) = parse_compressed_header(src,
                header, size_format)?;
            if regenerated > LITERALS_MAX { return Err(Error::BlockTooLarge); }
            let end = header_len + compressed;
            if src.len() < end { return Err(Error::Truncated); }
            let body = &src[header_len..end];
            let streams = if kind == LITERALS_TYPE_HUFFMAN {
                let (t, used) = huff::Table::parse(body)?;
                *table = Some(t);
                &body[used..]
            } else {
                body
            };
            let Some(t) = table.as_ref() else { return Err(Error::BadHuffmanTable) };
            if four { t.decode_4streams(streams, regenerated, out)?; }
            else { t.decode_stream(streams, regenerated, out)?; }
            Ok(end)
        }
        _ => unreachable!("the type field is two bits and all four are handled"),
    }
}

/// Sizes for the two Huffman forms. Returns
/// `(regenerated, compressed, header_len, four_streams)`.
/// # C: O(1)
fn parse_compressed_header(src: &[u8], header: u8, size_format: u8)
    -> Result<(usize, usize, usize, bool)>
{
    // Size format 0 is the only single-stream form; the other three all use
    // four interleaved streams and differ only in field width.
    let (header_len, size_bits, four) = match size_format {
        0 => (3usize, 10u32, false),
        1 => (3, 10, true),
        2 => (4, 14, true),
        _ => (5, 18, true),
    };
    if src.len() < header_len { return Err(Error::Truncated); }
    let mut v: u64 = 0;
    for (i, &b) in src[..header_len].iter().enumerate() { v |= (b as u64) << (8 * i); }
    let _ = header;
    let mask = (1u64 << size_bits) - 1;
    let regenerated = ((v >> 4) & mask) as usize;
    let compressed = ((v >> (4 + size_bits)) & mask) as usize;
    Ok((regenerated, compressed, header_len, four))
}

/// Emit a raw literals section for `lits`, choosing the narrowest header that
/// holds the length. The encoder never emits Huffman literals, so this is the
/// only writer.
/// # C: O(literals)
pub fn write_raw(lits: &[u8], out: &mut Vec<u8>) {
    const SIZE_FORMAT_5BIT_MAX: usize = (1 << 5) - 1;
    const SIZE_FORMAT_12BIT_MAX: usize = (1 << 12) - 1;
    let n = lits.len();
    if n <= SIZE_FORMAT_5BIT_MAX {
        out.push(LITERALS_TYPE_RAW | ((n as u8) << 3));
    } else if n <= SIZE_FORMAT_12BIT_MAX {
        // Size format 1: 12-bit length spanning two bytes.
        out.push(LITERALS_TYPE_RAW | (1 << LITERALS_SIZE_FORMAT_SHIFT) | ((n as u8 & 0x0F) << 4));
        out.push((n >> 4) as u8);
    } else {
        // Size format 3: 20-bit length spanning three bytes.
        out.push(LITERALS_TYPE_RAW | (3 << LITERALS_SIZE_FORMAT_SHIFT) | ((n as u8 & 0x0F) << 4));
        out.push((n >> 4) as u8);
        out.push((n >> 12) as u8);
    }
    out.extend_from_slice(lits);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    fn round_trip(lits: &[u8]) {
        let mut buf = Vec::new();
        write_raw(lits, &mut buf);
        let mut out = Vec::new();
        let mut table = None;
        let used = decode(&buf, &mut out, &mut table).expect("our own section decodes");
        assert_eq!(used, buf.len(), "the reader must consume exactly what was written");
        assert_eq!(out, lits);
    }

    #[test]
    fn raw_sections_round_trip_across_every_header_width() {
        // The three widths are chosen by length, so each boundary is a place a
        // one-byte-off header would silently shift the whole block.
        round_trip(&[]);
        round_trip(&[0xAB]);
        round_trip(&vec![0x11; 31]);
        round_trip(&vec![0x22; 32]);
        round_trip(&vec![0x33; 4095]);
        round_trip(&vec![0x44; 4096]);
    }

    #[test]
    fn an_rle_section_expands_one_byte() {
        // Type 1, size format 0, length 7, byte 0x5A.
        let src = [LITERALS_TYPE_RLE | (7 << 3), 0x5A];
        let mut out = Vec::new();
        let mut table = None;
        assert_eq!(decode(&src, &mut out, &mut table).unwrap(), 2);
        assert_eq!(out, vec![0x5A; 7]);
    }

    #[test]
    fn a_truncated_section_is_refused_rather_than_read_past() {
        let mut out = Vec::new();
        let mut table = None;
        assert_eq!(decode(&[], &mut out, &mut table).unwrap_err(), Error::Truncated);
        // Claims 31 raw literals, supplies two.
        assert_eq!(decode(&[LITERALS_TYPE_RAW | (31 << 3), 1, 2], &mut out, &mut table)
            .unwrap_err(), Error::Truncated);
    }

    #[test]
    fn reuse_without_a_previous_table_is_refused() {
        let mut out = Vec::new();
        let mut table = None;
        let src = [LITERALS_TYPE_HUFFMAN_REUSE, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode(&src, &mut out, &mut table).unwrap_err(), Error::BadHuffmanTable);
    }
}
