// Reverse bitstreams (RFC 8878 4.1).
//
// zstd writes its FSE/Huffman bitstreams FORWARD and reads them BACKWARD. The
// clean way to think about it: the byte slice is one little-endian big integer,
// `src[0]` least significant, and bit `i` of that integer is bit `i % 8` of
// `src[i / 8]`. The writer appends bits upward from the bottom; the reader
// starts at the top and walks down. So the LAST field written is the FIRST
// field read, which is why encoders emit sequences in reverse order.
//
// The top of the stream carries a single `1` marker bit; everything above it is
// zero padding to the byte boundary. Finding that marker is how the reader
// learns where the data ends.

extern crate alloc;
use alloc::vec::Vec;

use crate::{Error, Result};

/// Widest single read the format asks for: an offset code can carry 31 extra
/// bits, and an FSE state up to 9.
pub const MAX_READ_BITS: u32 = 32;

#[derive(Debug)]
pub struct RevReader<'a> {
    src: &'a [u8],
    /// Index of the next bit to read, counting down. Negative once the stream
    /// is spent.
    pos: i64,
    /// Set when a read asked for bits below the bottom of the stream. Those
    /// bits come back as zero; the caller checks this at the end, because a
    /// well-formed stream lands exactly on zero.
    overrun: bool,
}

impl<'a> RevReader<'a> {
    /// Position at the marker bit and step one below it.
    /// # C: O(1)
    pub fn new(src: &'a [u8]) -> Result<Self> {
        let Some((&last, _)) = src.split_last() else { return Err(Error::Truncated) };
        if last == 0 { return Err(Error::Truncated); }
        // Highest set bit in the last byte is the marker; data starts below it.
        let marker = (src.len() as i64 - 1) * 8 + (7 - last.leading_zeros() as i64);
        Ok(Self { src, pos: marker - 1, overrun: false })
    }

    /// Bits still unread. Zero exactly when a conforming stream is spent.
    /// # C: O(1)
    pub fn remaining(&self) -> i64 { self.pos + 1 }

    /// Whether any read fell off the bottom of the stream.
    /// # C: O(1)
    pub fn overran(&self) -> bool { self.overrun }

    /// Read `n` bits, most-significant first. Reads past the bottom return the
    /// available bits with zeros shifted in below, and latch `overrun`.
    /// # C: O(1)
    pub fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.consume(n);
        v
    }

    /// Read `n` bits without advancing. Huffman decoding needs the widest
    /// possible lookahead before it knows how many bits the symbol actually
    /// costs.
    /// # C: O(1)
    pub fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= MAX_READ_BITS, "read wider than the format uses");
        if n == 0 { return 0; }
        let hi = self.pos;
        let lo = hi - n as i64 + 1;
        if hi < 0 { return 0; }
        // Missing low bits are shifted in as zeros, matching how the format's
        // final partial read behaves.
        let shortfall = if lo < 0 { (-lo) as u32 } else { 0 };
        let lo = lo.max(0) as usize;
        let hi = hi as usize;
        let first = lo / 8;
        let shift = (lo % 8) as u32;
        let nbytes = (hi / 8) - first + 1;
        let mut acc: u64 = 0;
        for i in 0..nbytes {
            // A conforming reader never indexes past the slice: `hi` came from
            // the marker, which is inside it.
            acc |= (self.src[first + i] as u64) << (8 * i);
        }
        let want = n - shortfall;
        let mask = if want >= 64 { u64::MAX } else { (1u64 << want) - 1 };
        (((acc >> shift) & mask) << shortfall) as u32
    }

    /// Advance past `n` bits, latching `overrun` if that walks off the bottom.
    /// # C: O(1)
    pub fn consume(&mut self, n: u32) {
        if n == 0 { return; }
        let lo = self.pos - n as i64 + 1;
        if lo < 0 { self.overrun = true; }
        self.pos = lo - 1;
    }

    /// Read `n` bits and fail rather than zero-fill if the stream is short.
    /// Used where the format guarantees the bits exist, so a short read means
    /// the input is corrupt.
    /// # C: O(1)
    pub fn read_exact(&mut self, n: u32) -> Result<u32> {
        if (n as i64) > self.remaining() { return Err(Error::BitstreamOverrun); }
        Ok(self.read(n))
    }
}

/// Forward, least-significant-bit-first reader.
///
/// The format uses BOTH directions: FSE table descriptions and Huffman weight
/// headers are read forward from the first byte, while the data bitstreams they
/// describe are read backward. Mixing the two up is the classic zstd bug, so
/// they are separate types rather than a mode flag.
pub struct FwdReader<'a> {
    src: &'a [u8],
    /// Index of the next bit to read, counting up.
    pos: usize,
}

impl<'a> FwdReader<'a> {
    /// # C: O(1)
    pub fn new(src: &'a [u8]) -> Self { Self { src, pos: 0 } }

    /// Bytes consumed so far, rounded up — how much of the section the caller
    /// must skip to reach what follows.
    /// # C: O(1)
    pub fn bytes_used(&self) -> usize { (self.pos + 7) / 8 }

    /// Read `n` bits, least-significant first. Past the end reads as zeros,
    /// which is what the table-description parser's lookahead expects.
    /// # C: O(1)
    pub fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.pos += n as usize;
        v
    }

    /// Read `n` bits without consuming them. The distribution parser must
    /// decide how wide a field is from its value.
    /// # C: O(1)
    pub fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= MAX_READ_BITS, "peek wider than the format uses");
        if n == 0 { return 0; }
        let first = self.pos / 8;
        let shift = (self.pos % 8) as u32;
        let mut acc: u64 = 0;
        for i in 0..=((n + shift) as usize / 8) {
            if first + i >= self.src.len() { break; }
            acc |= (self.src[first + i] as u64) << (8 * i);
        }
        let mask = if n >= 32 { u32::MAX as u64 } else { (1u64 << n) - 1 };
        ((acc >> shift) & mask) as u32
    }

    /// Advance without reading.
    /// # C: O(1)
    pub fn skip(&mut self, n: u32) { self.pos += n as usize; }
}

/// Forward writer producing a stream `RevReader` reads back in reverse order.
pub struct RevWriter {
    out: Vec<u8>,
    /// Bits pending below a byte boundary, in the low `nbits`.
    acc: u64,
    nbits: u32,
}

impl RevWriter {
    /// # C: O(1)
    pub fn new() -> Self { Self { out: Vec::new(), acc: 0, nbits: 0 } }

    /// Append `n` bits of `value`, low bits first.
    /// # C: O(1) amortized
    pub fn push(&mut self, value: u32, n: u32) {
        debug_assert!(n <= MAX_READ_BITS, "write wider than the format uses");
        if n == 0 { return; }
        let mask = if n >= 32 { u32::MAX } else { (1u32 << n) - 1 };
        self.acc |= ((value & mask) as u64) << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    /// Append the marker bit and pad to a byte boundary.
    /// # C: O(1)
    pub fn finish(mut self) -> Vec<u8> {
        self.push(1, 1);
        if self.nbits > 0 { self.out.push(self.acc as u8); }
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn the_reader_returns_fields_in_reverse_write_order() {
        // This is the whole contract: an encoder emits sequences forward and
        // the decoder consumes them backward. If this inverts, every FSE
        // stream in the format decodes as noise.
        let mut w = RevWriter::new();
        w.push(0b101, 3);
        w.push(0b1100, 4);
        w.push(0b11111111, 8);
        let buf = w.finish();
        let mut r = RevReader::new(&buf).unwrap();
        assert_eq!(r.read(8), 0b11111111);
        assert_eq!(r.read(4), 0b1100);
        assert_eq!(r.read(3), 0b101);
        assert_eq!(r.remaining(), 0, "a conforming stream lands exactly on zero");
        assert!(!r.overran());
    }

    #[test]
    fn a_stream_that_ends_on_a_byte_boundary_still_carries_its_marker() {
        // 7 bits of data + the marker fills exactly one byte. If `finish`
        // dropped the marker here the reader would mistake a data bit for it.
        let mut w = RevWriter::new();
        w.push(0b1010101, 7);
        let buf = w.finish();
        assert_eq!(buf, vec![0b1101_0101]);
        let mut r = RevReader::new(&buf).unwrap();
        assert_eq!(r.read(7), 0b1010101);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn zero_width_reads_and_writes_are_identities() {
        let mut w = RevWriter::new();
        w.push(0, 0);
        w.push(0xFF, 8);
        w.push(0, 0);
        let buf = w.finish();
        let mut r = RevReader::new(&buf).unwrap();
        assert_eq!(r.read(0), 0);
        assert_eq!(r.read(8), 0xFF);
        assert_eq!(r.read(0), 0);
    }

    #[test]
    fn reading_past_the_bottom_zero_fills_and_latches_overrun() {
        // The zero-fill matters: FSE's last state read may legitimately span
        // the bottom, and the decoder distinguishes that from corruption by
        // checking `overran` after the symbol count is satisfied.
        let mut w = RevWriter::new();
        w.push(0b11, 2);
        let buf = w.finish();
        let mut r = RevReader::new(&buf).unwrap();
        assert_eq!(r.read(4), 0b1100, "two real bits, two zeros below");
        assert!(r.overran());
    }

    #[test]
    fn a_wide_field_spanning_five_bytes_round_trips() {
        // 32 bits at a 7-bit offset touches five bytes — the widest gather the
        // reader ever performs.
        let mut w = RevWriter::new();
        w.push(0b1111111, 7);
        w.push(0xDEAD_BEEF, 32);
        let buf = w.finish();
        let mut r = RevReader::new(&buf).unwrap();
        assert_eq!(r.read(32), 0xDEAD_BEEF);
        assert_eq!(r.read(7), 0b1111111);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn an_empty_or_all_zero_stream_has_no_marker() {
        assert_eq!(RevReader::new(&[]).unwrap_err(), Error::Truncated);
        assert_eq!(RevReader::new(&[0x00]).unwrap_err(), Error::Truncated);
    }
}
