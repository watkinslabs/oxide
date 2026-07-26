// Top-level decompression: frames, blocks, and the state that spans them.
//
// Two pieces of state outlive a block and are the reason this is a struct
// rather than a free function chain: the Huffman table (a block may reuse the
// previous one) and the FSE tables plus repeat offsets (likewise). Losing
// either across a block boundary decodes multi-block frames into garbage.

extern crate alloc;
use alloc::vec::Vec;

use crate::frame::{self, BlockKind};
use crate::huff;
use crate::literals;
use crate::sequences::{self, INITIAL_REPEAT_OFFSETS};
use crate::uapi::{BLOCK_HEADER_LEN, CHECKSUM_LEN, CHECKSUM_SEED, MAGIC_SKIPPABLE_LOW,
    MAGIC_SKIPPABLE_MASK};
use crate::xxhash;
use crate::{Error, Result};

/// Reusable decoder. Holding one across calls avoids rebuilding the predefined
/// tables per page, which is the whole per-call cost for small inputs.
///
/// Everything large lives behind `Vec`, so the struct itself is a handful of
/// pointers and never sizes a caller's stack frame -- the failure mode that
/// made the vendored decoder unusable in the kernel.
#[derive(Default)]
pub struct Decoder {
    huffman: Option<huff::Table>,
    fse: sequences::Tables,
    literals: Vec<u8>,
}

impl Decoder {
    /// # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Decompress one frame, appending to `out`. Returns the bytes of `src`
    /// consumed, so a caller holding concatenated frames can advance.
    /// # C: O(decompressed size)
    pub fn decompress_frame(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<usize> {
        const MAGIC_LEN: usize = 4;
        const SKIPPABLE_SIZE_LEN: usize = 4;
        if src.len() >= MAGIC_LEN + SKIPPABLE_SIZE_LEN {
            let magic = u32::from_le_bytes(src[..MAGIC_LEN].try_into().expect("four bytes"));
            if magic & MAGIC_SKIPPABLE_MASK == MAGIC_SKIPPABLE_LOW {
                // Skippable frames carry caller metadata, not content. Stepping
                // over them is required to decode a concatenated stream.
                let n = u32::from_le_bytes(
                    src[MAGIC_LEN..MAGIC_LEN + SKIPPABLE_SIZE_LEN].try_into()
                        .expect("four bytes")) as usize;
                let end = MAGIC_LEN + SKIPPABLE_SIZE_LEN + n;
                if src.len() < end { return Err(Error::Truncated); }
                return Ok(end);
            }
        }

        let header = frame::read_header(src)?;
        // Offsets may not reach before this frame's own output, even when the
        // caller passed a buffer that already holds an earlier frame.
        let window_start = out.len();
        let mut at = header.len;
        // Tables and repeat offsets are per-frame, not per-decoder.
        self.huffman = None;
        self.fse = sequences::Tables::default();
        let mut rep = INITIAL_REPEAT_OFFSETS;

        loop {
            let bh = frame::read_block_header(&src[at.min(src.len())..])?;
            at += BLOCK_HEADER_LEN;
            match bh.kind {
                BlockKind::Raw => {
                    let end = at + bh.size;
                    if src.len() < end { return Err(Error::Truncated); }
                    out.extend_from_slice(&src[at..end]);
                    at = end;
                }
                BlockKind::Rle => {
                    let Some(&byte) = src.get(at) else { return Err(Error::Truncated) };
                    out.resize(out.len() + bh.size, byte);
                    at += 1;
                }
                BlockKind::Compressed => {
                    let end = at + bh.size;
                    if src.len() < end { return Err(Error::Truncated); }
                    self.decode_compressed(&src[at..end], out, &mut rep, window_start,
                        header.window_size)?;
                    at = end;
                }
            }
            if bh.last { break; }
        }

        if let Some(want) = header.content_size {
            if (out.len() - window_start) as u64 != want { return Err(Error::LiteralsMismatch); }
        }
        if header.has_checksum {
            if src.len() < at + CHECKSUM_LEN { return Err(Error::Truncated); }
            let stored = u32::from_le_bytes(
                src[at..at + CHECKSUM_LEN].try_into().expect("four bytes"));
            // Only the low 32 bits of the digest are stored.
            let got = xxhash::hash(&out[window_start..], CHECKSUM_SEED) as u32;
            if stored != got { return Err(Error::ChecksumMismatch); }
            at += CHECKSUM_LEN;
        }
        Ok(at)
    }

    fn decode_compressed(&mut self, src: &[u8], out: &mut Vec<u8>, rep: &mut [u32; 3],
        window_start: usize, window_size: u64) -> Result<()>
    {
        self.literals.clear();
        let used = literals::decode(src, &mut self.literals, &mut self.huffman)?;
        if used > src.len() { return Err(Error::Truncated); }
        sequences::decode_and_execute(&src[used..], &self.literals, out, &mut self.fse, rep,
            window_start, window_size)
    }
}

/// Decompress every frame in `src` into a fresh buffer.
/// # C: O(decompressed size)
pub fn decompress(src: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut d = Decoder::new();
    let mut at = 0;
    while at < src.len() {
        at += d.decompress_frame(&src[at..], &mut out)?;
    }
    Ok(out)
}

/// Decompress into a caller-owned buffer, returning the byte count.
///
/// This is the shape zram wants: the destination is a page it already owns, and
/// a frame that decodes to more than a page is an error rather than a
/// reallocation.
/// # C: O(decompressed size)
pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    let out = decompress(src)?;
    if out.len() > dst.len() { return Err(Error::OutputFull); }
    dst[..out.len()].copy_from_slice(&out);
    Ok(out.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn a_raw_block_frame_decodes_to_its_content() {
        let mut buf = Vec::new();
        frame::write_header(4, false, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        assert_eq!(decompress(&buf).unwrap(), b"abcd");
    }

    #[test]
    fn an_rle_block_expands_without_carrying_its_bytes() {
        let mut buf = Vec::new();
        frame::write_header(1000, false, &mut buf);
        frame::write_block_header(true, BlockKind::Rle, 1000, &mut buf);
        buf.push(b'z');
        assert_eq!(decompress(&buf).unwrap(), vec![b'z'; 1000]);
    }

    #[test]
    fn a_declared_content_size_that_disagrees_is_refused() {
        // Silently accepting this would hand zram a short page.
        let mut buf = Vec::new();
        frame::write_header(99, false, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        assert_eq!(decompress(&buf).unwrap_err(), Error::LiteralsMismatch);
    }

    #[test]
    fn a_corrupt_checksum_is_caught() {
        let mut buf = Vec::new();
        frame::write_header(4, true, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        let good = xxhash::hash(b"abcd", CHECKSUM_SEED) as u32;
        buf.extend_from_slice(&good.to_le_bytes());
        assert_eq!(decompress(&buf).unwrap(), b"abcd");

        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        assert_eq!(decompress(&buf).unwrap_err(), Error::ChecksumMismatch);
    }

    #[test]
    fn multiple_blocks_in_one_frame_concatenate() {
        let mut buf = Vec::new();
        frame::write_header(7, false, &mut buf);
        frame::write_block_header(false, BlockKind::Raw, 3, &mut buf);
        buf.extend_from_slice(b"abc");
        frame::write_block_header(true, BlockKind::Rle, 4, &mut buf);
        buf.push(b'x');
        assert_eq!(decompress(&buf).unwrap(), b"abcxxxx");
    }

    #[test]
    fn a_skippable_frame_is_stepped_over() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC_SKIPPABLE_LOW.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(b"xxx");
        frame::write_header(2, false, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 2, &mut buf);
        buf.extend_from_slice(b"hi");
        assert_eq!(decompress(&buf).unwrap(), b"hi");
    }

    #[test]
    fn decompress_into_reports_a_short_destination_rather_than_truncating() {
        let mut buf = Vec::new();
        frame::write_header(4, false, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        let mut dst = [0u8; 2];
        assert_eq!(decompress_into(&buf, &mut dst).unwrap_err(), Error::OutputFull);
        let mut dst = [0u8; 8];
        assert_eq!(decompress_into(&buf, &mut dst).unwrap(), 4);
        assert_eq!(&dst[..4], b"abcd");
    }

    #[test]
    fn a_truncated_frame_never_reads_past_its_input() {
        let mut buf = Vec::new();
        frame::write_header(4096, false, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4096, &mut buf);
        buf.extend_from_slice(b"only a few bytes");
        assert_eq!(decompress(&buf).unwrap_err(), Error::Truncated);
    }
}
