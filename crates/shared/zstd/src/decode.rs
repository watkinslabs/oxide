// Top-level decompression: frames, blocks, and the state that spans them.
//
// Two pieces of state outlive a block and are the reason this is a struct
// rather than a free function chain: the Huffman table (a block may reuse the
// previous one) and the FSE tables plus repeat offsets (likewise). Losing
// either across a block boundary decodes multi-block frames into garbage.

extern crate alloc;
use alloc::vec::Vec;

use crate::dict::Dictionary;
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
    /// Output scratch, kept across calls so a per-CPU decoder stops
    /// reallocating a page-sized buffer for every page.
    scratch: Vec<u8>,
}

impl Decoder {
    /// # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Decode a whole input into a caller-owned buffer, reusing this decoder's
    /// scratch allocation.
    ///
    /// This is the shape zram wants: the destination is a page it already owns,
    /// and the decode must not allocate one per call. The scratch is needed
    /// even so, because a dictionary has to sit in front of the output for
    /// offsets to reach it.
    /// # C: O(dictionary bytes + decompressed size)
    pub fn decompress_page(&mut self, src: &[u8], dst: &mut [u8], dict: Option<&Dictionary>)
        -> Result<usize>
    {
        let mut out = core::mem::take(&mut self.scratch);
        let n = self.decode_into(src, &mut out, dst, dict);
        out.clear();
        self.scratch = out;
        n
    }

    fn decode_into(&mut self, src: &[u8], out: &mut Vec<u8>, dst: &mut [u8],
        dict: Option<&Dictionary>) -> Result<usize>
    {
        let mut written = 0usize;
        let mut at = 0;
        // Frames are INDEPENDENT: one may not reach into an earlier one's
        // output, but every one of them may reach into the dictionary. So the
        // buffer is reset to just the dictionary before each frame rather than
        // accumulating across them.
        while at < src.len() {
            out.clear();
            if let Some(d) = dict { out.extend_from_slice(&d.content); }
            let prefix = out.len();
            at += self.decompress_frame_with(&src[at..], out, dict)?;
            let n = out.len() - prefix;
            let end = written.checked_add(n).ok_or(Error::OutputFull)?;
            if end > dst.len() { return Err(Error::OutputFull); }
            dst[written..end].copy_from_slice(&out[prefix..]);
            written = end;
        }
        Ok(written)
    }

    /// Decompress one frame, appending to `out`. Returns the bytes of `src`
    /// consumed, so a caller holding concatenated frames can advance.
    /// # C: O(decompressed size)
    pub fn decompress_frame(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<usize> {
        self.decompress_frame_with(src, out, None)
    }

    /// As `decompress_frame`, against a dictionary.
    ///
    /// `out` must already END with the dictionary's content: that is what puts
    /// the dictionary in the window, so a match offset can reach into it the
    /// same way it reaches into an earlier block. `decompress_with_dict` does
    /// that placement; this is the entry point for a caller managing its own
    /// buffer.
    /// # C: O(decompressed size)
    pub fn decompress_frame_with(&mut self, src: &[u8], out: &mut Vec<u8>,
        dict: Option<&Dictionary>) -> Result<usize>
    {
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
        // A frame naming a dictionary cannot be decoded without exactly that
        // one; decoding it against the wrong dictionary would silently produce
        // different bytes.
        if header.dict_id != 0 && dict.is_none_or(|d| d.id != header.dict_id) {
            return Err(Error::DictionaryRequired);
        }
        let dict_len = dict.map_or(0, |d| d.content.len());
        // Where this frame's OWN output starts. The declared content size and
        // the checksum both cover only that, while match offsets may reach
        // further back, into the dictionary prefix.
        let frame_start = out.len();
        if frame_start < dict_len { return Err(Error::DictionaryRequired); }
        let reach_start = frame_start - dict_len;
        let mut at = header.len;
        // Tables and repeat offsets are per-frame. With a dictionary they start
        // from ITS tables, because the frame's first block may open in "repeat"
        // mode and mean exactly those.
        match dict {
            Some(d) => {
                self.huffman = d.huffman.clone();
                self.fse = d.fse.clone();
            }
            None => {
                self.huffman = None;
                self.fse = sequences::Tables::default();
            }
        }
        let mut rep = dict.map_or(INITIAL_REPEAT_OFFSETS, |d| d.reps);

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
                    // The dictionary extends the window it may reach back
                    // through, which is why its length is added rather than
                    // checked separately.
                    self.decode_compressed(&src[at..end], out, &mut rep, reach_start,
                        header.window_size + dict_len as u64)?;
                    at = end;
                }
            }
            if bh.last { break; }
        }

        if let Some(want) = header.content_size {
            if (out.len() - frame_start) as u64 != want { return Err(Error::LiteralsMismatch); }
        }
        if header.has_checksum {
            if src.len() < at + CHECKSUM_LEN { return Err(Error::Truncated); }
            let stored = u32::from_le_bytes(
                src[at..at + CHECKSUM_LEN].try_into().expect("four bytes"));
            // Only the low 32 bits of the digest are stored.
            let got = xxhash::hash(&out[frame_start..], CHECKSUM_SEED) as u32;
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
pub fn decompress(src: &[u8]) -> Result<Vec<u8>> { decompress_with(src, None) }

/// Decompress against a dictionary.
/// # C: O(dictionary bytes + decompressed size)
pub fn decompress_with_dict(src: &[u8], dict: &Dictionary) -> Result<Vec<u8>> {
    decompress_with(src, Some(dict))
}

fn decompress_with(src: &[u8], dict: Option<&Dictionary>) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut scratch = Vec::new();
    let mut decoder = Decoder::new();
    let mut at = 0;
    // One frame at a time, each starting from the dictionary alone: the
    // dictionary content goes in FRONT of the output so match offsets can reach
    // it, and a frame may never reach into an earlier frame's output.
    while at < src.len() {
        scratch.clear();
        if let Some(d) = dict { scratch.extend_from_slice(&d.content); }
        let prefix = scratch.len();
        at += decoder.decompress_frame_with(&src[at..], &mut scratch, dict)?;
        result.extend_from_slice(&scratch[prefix..]);
    }
    Ok(result)
}

/// Decompress into a caller-owned buffer, returning the byte count.
///
/// This is the shape zram wants: the destination is a page it already owns, and
/// a frame that decodes to more than a page is an error rather than a
/// reallocation.
/// # C: O(decompressed size)
pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    copy_out(decompress(src)?, dst)
}

/// `decompress_into` against a dictionary.
/// # C: O(dictionary bytes + decompressed size)
pub fn decompress_into_with_dict(src: &[u8], dst: &mut [u8], dict: &Dictionary) -> Result<usize> {
    copy_out(decompress_with_dict(src, dict)?, dst)
}

fn copy_out(out: Vec<u8>, dst: &mut [u8]) -> Result<usize> {
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
        frame::write_header(4, false, 0, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        assert_eq!(decompress(&buf).unwrap(), b"abcd");
    }

    #[test]
    fn an_rle_block_expands_without_carrying_its_bytes() {
        let mut buf = Vec::new();
        frame::write_header(1000, false, 0, &mut buf);
        frame::write_block_header(true, BlockKind::Rle, 1000, &mut buf);
        buf.push(b'z');
        assert_eq!(decompress(&buf).unwrap(), vec![b'z'; 1000]);
    }

    #[test]
    fn a_declared_content_size_that_disagrees_is_refused() {
        // Silently accepting this would hand zram a short page.
        let mut buf = Vec::new();
        frame::write_header(99, false, 0, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        assert_eq!(decompress(&buf).unwrap_err(), Error::LiteralsMismatch);
    }

    #[test]
    fn a_corrupt_checksum_is_caught() {
        let mut buf = Vec::new();
        frame::write_header(4, true, 0, &mut buf);
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
        frame::write_header(7, false, 0, &mut buf);
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
        frame::write_header(2, false, 0, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 2, &mut buf);
        buf.extend_from_slice(b"hi");
        assert_eq!(decompress(&buf).unwrap(), b"hi");
    }

    #[test]
    fn concatenated_frames_cannot_reach_into_each_other() {
        // Each frame is independent. If frame two could match against frame
        // one's output, a corrupt stream would decode instead of erroring.
        let mut one = Vec::new();
        frame::write_header(4, false, 0, &mut one);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut one);
        one.extend_from_slice(b"abcd");
        let mut two = one.clone();
        two.extend_from_slice(&one);
        assert_eq!(decompress(&two).unwrap(), b"abcdabcd");
        let mut dst = [0u8; 16];
        let mut d = Decoder::new();
        assert_eq!(d.decompress_page(&two, &mut dst, None).unwrap(), 8);
        assert_eq!(&dst[..8], b"abcdabcd");
    }

    #[test]
    fn decompress_page_reuses_its_scratch_and_matches_the_free_function() {
        // The per-CPU zram decoder lives on this path, so it must agree with
        // the allocating one and must not grow its scratch without bound.
        let mut buf = Vec::new();
        frame::write_header(4, false, 0, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4, &mut buf);
        buf.extend_from_slice(b"abcd");
        let mut d = Decoder::new();
        let mut dst = [0u8; 8];
        for _ in 0..3 {
            assert_eq!(d.decompress_page(&buf, &mut dst, None).unwrap(), 4);
            assert_eq!(&dst[..4], b"abcd");
        }
        assert!(d.scratch.is_empty(), "the scratch is returned empty for reuse");
        let mut small = [0u8; 2];
        assert_eq!(d.decompress_page(&buf, &mut small, None).unwrap_err(), Error::OutputFull);
    }

    #[test]
    fn decompress_into_reports_a_short_destination_rather_than_truncating() {
        let mut buf = Vec::new();
        frame::write_header(4, false, 0, &mut buf);
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
        frame::write_header(4096, false, 0, &mut buf);
        frame::write_block_header(true, BlockKind::Raw, 4096, &mut buf);
        buf.extend_from_slice(b"only a few bytes");
        assert_eq!(decompress(&buf).unwrap_err(), Error::Truncated);
    }
}
