// Top-level compression.
//
// The output is a conforming zstd frame using a deliberately narrow subset:
// single-segment frames, raw literals, and sequences coded with the PREDEFINED
// FSE tables. Every zstd decoder accepts it.
//
// Why that subset. Huffman literals need a weight-table builder and an entropy
// pass; custom FSE tables need normalization and a table description writer.
// Both buy ratio, and both are a second pass over the block plus a few
// kilobytes of tables. On the swap path, where this compresses one page at a
// time, the sequence coding is where the compression actually comes from -- the
// literals of a compressible page are mostly incompressible residue anyway.
//
// The encoder never emits a frame LARGER than the input: if the compressed form
// does not win, the block is re-emitted raw, which is what zram needs to decide
// a page is incompressible.

extern crate alloc;
use alloc::vec::Vec;

use crate::bits::RevWriter;
use crate::frame::{self, BlockKind};
use crate::fse_encode::{EncTable, State};
use crate::literals;
use crate::match_finder::{Finder, Match, MIN_MATCH};
use crate::tables::{self, LL_BASE, LL_DEFAULT, LL_DEFAULT_LOG, LL_EXTRA, ML_BASE, ML_DEFAULT,
    ML_DEFAULT_LOG, ML_EXTRA, OF_DEFAULT, OF_DEFAULT_LOG};
use crate::uapi::{BLOCK_HEADER_LEN, BLOCK_SIZE_MAX, SEQ_COUNT_ONE_BYTE_MAX,
    SEQ_COUNT_TWO_BYTE_BASE, SEQ_COUNT_TWO_BYTE_MARKER};
use crate::{Error, Result};

/// Compression effort. Only the match-finder's chain depth varies: the entropy
/// stage is the same at every level, so these are honest about what they buy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Level { Fast, Default, Best }

impl Level {
    fn depth(self) -> usize {
        match self {
            Level::Fast => 4,
            Level::Default => 16,
            Level::Best => 64,
        }
    }
}

impl Default for Level {
    fn default() -> Self { Level::Default }
}

/// Offsets 1..3 are repeat codes, so a literal offset is biased past them.
const OFFSET_BIAS: u32 = 3;

struct Seq {
    literal_len: u32,
    match_len: u32,
    /// Already biased by `OFFSET_BIAS`.
    offset_value: u32,
}

/// Reusable encoder. The three FSE tables are built once and reused for every
/// page, which is the bulk of the per-call cost at this size.
///
/// As with `Decoder`, everything large is behind a `Vec`: this struct is a few
/// words and never sizes a caller's stack frame.
pub struct Encoder {
    ll: EncTable,
    of: EncTable,
    ml: EncTable,
    level: Level,
    literals: Vec<u8>,
    seqs: Vec<Seq>,
    body: Vec<u8>,
}

impl Encoder {
    /// # C: O(table size)
    pub fn new(level: Level) -> Self {
        // The predefined distributions are compile-time constants and are
        // known-valid; a failure here is a bug in this crate, not in input.
        Self {
            ll: EncTable::from_normalized(&LL_DEFAULT, LL_DEFAULT_LOG)
                .expect("predefined literal-length table"),
            of: EncTable::from_normalized(&OF_DEFAULT, OF_DEFAULT_LOG)
                .expect("predefined offset table"),
            ml: EncTable::from_normalized(&ML_DEFAULT, ML_DEFAULT_LOG)
                .expect("predefined match-length table"),
            level,
            literals: Vec::new(),
            seqs: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Compress `src` into a complete frame appended to `out`.
    /// # C: O(len * level depth)
    pub fn compress_frame(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if src.len() > BLOCK_SIZE_MAX { return Err(Error::BlockTooLarge); }
        frame::write_header(src.len() as u64, false, out);
        if src.is_empty() {
            frame::write_block_header(true, BlockKind::Raw, 0, out);
            return Ok(());
        }
        // A page of one repeated byte is the single most common compressible
        // case on the swap path, and RLE encodes it in one byte.
        if src.iter().all(|&b| b == src[0]) {
            frame::write_block_header(true, BlockKind::Rle, src.len(), out);
            out.push(src[0]);
            return Ok(());
        }
        self.parse(src);
        self.emit_body()?;
        // Only worth a compressed block if it actually beat the bytes.
        if self.body.len() < src.len() {
            frame::write_block_header(true, BlockKind::Compressed, self.body.len(), out);
            out.extend_from_slice(&self.body);
        } else {
            frame::write_block_header(true, BlockKind::Raw, src.len(), out);
            out.extend_from_slice(src);
        }
        Ok(())
    }

    /// Greedy LZ77 parse into `self.literals` and `self.seqs`.
    fn parse(&mut self, src: &[u8]) {
        self.literals.clear();
        self.seqs.clear();
        let mut finder = Finder::new(src.len(), self.level.depth());
        let mut at = 0usize;
        let mut lit_start = 0usize;
        while at + MIN_MATCH <= src.len() {
            match finder.find(src, at) {
                Some(Match { distance, length }) => {
                    self.literals.extend_from_slice(&src[lit_start..at]);
                    self.seqs.push(Seq {
                        literal_len: (at - lit_start) as u32,
                        match_len: length as u32,
                        offset_value: distance as u32 + OFFSET_BIAS,
                    });
                    // Every covered position still enters the chain: skipping
                    // them costs ratio on the next match for no real speed.
                    for i in at..at + length { finder.insert(src, i); }
                    at += length;
                    lit_start = at;
                }
                None => {
                    finder.insert(src, at);
                    at += 1;
                }
            }
        }
        self.literals.extend_from_slice(&src[lit_start..]);
    }

    /// Serialise literals + sequences into `self.body`.
    fn emit_body(&mut self) -> Result<()> {
        self.body.clear();
        literals::write_raw(&self.literals, &mut self.body);
        write_seq_count(self.seqs.len(), &mut self.body)?;
        if self.seqs.is_empty() { return Ok(()); }
        // All three tables predefined: mode field is four zero bit-pairs.
        self.body.push(0);

        let last = self.seqs.last().expect("checked non-empty");
        let last_ll = tables::ll_code(last.literal_len);
        let last_ml = tables::ml_code(last.match_len);
        let last_of = tables::of_code(last.offset_value);

        let mut w = RevWriter::new();
        // The states are seeded from the LAST sequence, because that is the
        // first one the decoder will read.
        let mut ml_s = State::init(&self.ml, last_ml);
        let mut of_s = State::init(&self.of, last_of);
        let mut ll_s = State::init(&self.ll, last_ll);
        push_extra(&mut w, last, last_ll, last_ml, last_of);

        // Backward over the remaining sequences. Symbol order here is offset,
        // match-length, literal-length -- the reverse of the order the decoder
        // advances its states in.
        for seq in self.seqs.iter().rev().skip(1) {
            let ll_code = tables::ll_code(seq.literal_len);
            let ml_code = tables::ml_code(seq.match_len);
            let of_code = tables::of_code(seq.offset_value);
            of_s.encode(of_code, &mut w);
            ml_s.encode(ml_code, &mut w);
            ll_s.encode(ll_code, &mut w);
            push_extra(&mut w, seq, ll_code, ml_code, of_code);
        }
        // Flushed match-length, offset, literal-length so the decoder reads
        // them back as literal-length, offset, match-length.
        ml_s.flush(&mut w);
        of_s.flush(&mut w);
        ll_s.flush(&mut w);
        self.body.extend_from_slice(&w.finish());
        Ok(())
    }
}

/// Extra bits for one sequence: literal-length, match-length, offset, so the
/// decoder reads them back offset first.
fn push_extra(w: &mut RevWriter, seq: &Seq, ll_code: u8, ml_code: u8, of_code: u8) {
    w.push(seq.literal_len - LL_BASE[ll_code as usize], LL_EXTRA[ll_code as usize] as u32);
    w.push(seq.match_len - ML_BASE[ml_code as usize], ML_EXTRA[ml_code as usize] as u32);
    w.push(seq.offset_value - tables::offset_baseline(of_code),
        tables::offset_extra_bits(of_code));
}

/// # C: O(1)
fn write_seq_count(n: usize, out: &mut Vec<u8>) -> Result<()> {
    const TWO_BYTE_MAX: usize = SEQ_COUNT_TWO_BYTE_BASE as usize - 1;
    const THREE_BYTE_MAX: usize = SEQ_COUNT_TWO_BYTE_BASE as usize + u16::MAX as usize;
    if n <= SEQ_COUNT_ONE_BYTE_MAX as usize {
        out.push(n as u8);
    } else if n <= TWO_BYTE_MAX {
        out.push(((n >> 8) + 128) as u8);
        out.push(n as u8);
    } else if n <= THREE_BYTE_MAX {
        let v = n - SEQ_COUNT_TWO_BYTE_BASE as usize;
        out.push(SEQ_COUNT_TWO_BYTE_MARKER);
        out.push(v as u8);
        out.push((v >> 8) as u8);
    } else {
        return Err(Error::BlockTooLarge);
    }
    Ok(())
}

/// Compress `src` into a fresh buffer at the default level.
/// # C: O(len)
pub fn compress(src: &[u8], level: Level) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    Encoder::new(level).compress_frame(src, &mut out)?;
    Ok(out)
}

/// Compress into a caller-owned buffer, returning the frame length.
///
/// `Error::OutputFull` is how zram learns a page did not compress into the
/// space it was willing to spend.
/// # C: O(len)
pub fn compress_into(src: &[u8], dst: &mut [u8], level: Level) -> Result<usize> {
    let out = compress(src, level)?;
    if out.len() > dst.len() { return Err(Error::OutputFull); }
    dst[..out.len()].copy_from_slice(&out);
    Ok(out.len())
}

/// Largest frame `compress` can produce for `len` input bytes: the raw-block
/// fallback plus its headers.
/// # C: O(1)
pub fn max_compressed_len(len: usize) -> usize {
    const MAX_FRAME_HEADER: usize = 4 + 1 + 8;
    MAX_FRAME_HEADER + BLOCK_HEADER_LEN + len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decompress;
    extern crate std;
    use std::vec;

    fn round_trip(src: &[u8]) -> Vec<u8> {
        let frame = compress(src, Level::Default).expect("compression succeeds");
        assert!(frame.len() <= max_compressed_len(src.len()), "frame within the bound");
        let back = decompress(&frame).expect("our own frame decodes");
        assert_eq!(back, src, "round trip must be exact");
        frame
    }

    #[test]
    fn empty_and_tiny_inputs_round_trip() {
        round_trip(b"");
        round_trip(b"a");
        round_trip(b"ab");
        round_trip(b"abc");
        round_trip(b"abcd");
    }

    #[test]
    fn a_uniform_page_becomes_an_rle_block() {
        let src = vec![0u8; 4096];
        let frame = round_trip(&src);
        // Header + block header + one byte. Anything larger means the RLE path
        // was missed, which is the most common page on the swap path.
        assert!(frame.len() <= 12, "a uniform page cost {} bytes", frame.len());
    }

    #[test]
    fn a_repetitive_page_actually_compresses() {
        let mut src = Vec::new();
        while src.len() < 4096 { src.extend_from_slice(b"the quick brown fox jumps! "); }
        src.truncate(4096);
        let frame = round_trip(&src);
        assert!(frame.len() < src.len() / 4, "repetitive page cost {} bytes", frame.len());
    }

    #[test]
    fn incompressible_input_falls_back_to_a_raw_block() {
        // A frame must never exceed the input by more than its headers,
        // otherwise zram would store more than the page it started with.
        let src: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        let frame = round_trip(&src);
        assert!(frame.len() <= src.len() + 16, "expansion of {} bytes", frame.len() - src.len());
    }

    #[test]
    fn every_page_of_a_structured_buffer_round_trips() {
        // Sweeps lengths across the literal-header width boundaries and the
        // sequence-count width boundary.
        for len in [1usize, 31, 32, 127, 128, 255, 256, 1023, 4095, 4096, 8192] {
            let src: Vec<u8> = (0..len).map(|i| (i % 61) as u8).collect();
            round_trip(&src);
        }
    }

    #[test]
    fn long_runs_and_long_matches_round_trip() {
        // Match lengths past 34 leave the single-code range and start using
        // extra bits, which is a different path through the tables.
        let mut src = vec![b'x'; 300];
        src.extend_from_slice(b"boundary");
        src.extend_from_slice(&vec![b'y'; 1000]);
        src.extend_from_slice(b"boundary");
        src.extend_from_slice(&vec![b'x'; 300]);
        round_trip(&src);
    }

    #[test]
    fn compress_into_reports_a_short_destination() {
        let src = vec![7u8; 4096];
        let mut dst = [0u8; 4];
        assert_eq!(compress_into(&src, &mut dst, Level::Fast).unwrap_err(), Error::OutputFull);
        let mut dst = [0u8; 64];
        let n = compress_into(&src, &mut dst, Level::Fast).unwrap();
        assert_eq!(decompress(&dst[..n]).unwrap(), src);
    }

    #[test]
    fn every_level_produces_a_decodable_frame() {
        let mut src = Vec::new();
        while src.len() < 8192 { src.extend_from_slice(b"repeat me repeat me repeat "); }
        for level in [Level::Fast, Level::Default, Level::Best] {
            let frame = compress(&src, level).unwrap();
            assert_eq!(decompress(&frame).unwrap(), src, "level {level:?}");
        }
    }
}
