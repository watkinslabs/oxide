//! LZNT1: the compression a compressed attribute's clusters hold.
//!
//! A compressed attribute is stored in units of sixteen clusters. Each unit is
//! either stored whole — in which case its clusters are ordinary data — or
//! compressed into FEWER clusters, with the rest of the unit a hole. So the
//! runlist of a compressed file has holes that are not holes: they are the
//! space the compression saved, and reading them as zeros returns zeros where
//! the file has data.
//!
//! Within a unit the data is a sequence of 4096-byte chunks, each with a
//! two-byte header saying its packed length and whether it is compressed at
//! all. A chunk's back-references address a window whose width GROWS as the
//! chunk fills, which is what makes the same sixteen-bit pair mean different
//! things at different points in one chunk.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::LZNT_CHUNK_SIZE;

/// How far back a reference can reach, at each stage of a chunk.
const MAX_OFFSETS: [usize; 9] = [0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000];

/// The bit of a chunk header that says the chunk is compressed.
const CHUNK_COMPRESSED: u16 = 0x8000;
/// The header's low bits hold the packed length, less three.
const CHUNK_LENGTH_MASK: u16 = (LZNT_CHUNK_SIZE - 1) as u16;
/// Bytes of a chunk header.
const CHUNK_HEADER_BYTES: usize = 2;
/// The shortest match a pair can encode.
const MIN_MATCH: usize = 3;

/// Why a compressed stream was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LzntError {
    /// A chunk reaches past the bytes there are.
    Truncated,
    /// A back-reference points before the start of its chunk.
    BadReference,
    /// A chunk decompressed to more than a chunk.
    Overrun,
}

impl LzntError {
    /// # C: O(1)
    pub fn errno(self) -> Errno { Errno::Eio }
}

/// How wide the offset field is at this point in a chunk.
///
/// The split between offset and length moves as the chunk fills: early in a
/// chunk a reference cannot reach far, so fewer bits are spent on it and more
/// on the length. A fixed split decodes every pair after the first sixteen
/// bytes wrongly.
/// # C: O(1)
fn window_index(produced: usize) -> usize {
    let mut index = 0usize;
    while index < MAX_OFFSETS.len() - 1 && MAX_OFFSETS[index] < produced { index += 1; }
    index
}

/// Split a packed pair into its offset and length. # C: O(1)
fn parse_pair(pair: u16, index: usize) -> (usize, usize) {
    let shift = 12 - index;
    let offset = 1 + (usize::from(pair) >> shift);
    let length = MIN_MATCH + (usize::from(pair) & ((1usize << shift) - 1));
    (offset, length)
}

/// Pack an offset and length into a pair. # C: O(1)
fn make_pair(offset: usize, length: usize, index: usize) -> u16 {
    let shift = 12 - index;
    (((offset - 1) << shift) | ((length - MIN_MATCH) & ((1usize << shift) - 1))) as u16
}

/// Decompress one chunk's body into `out`, returning how many bytes it
/// produced. # C: O(chunk bytes)
fn chunk(out: &mut Vec<u8>, limit: usize, packed: &[u8]) -> Result<usize, LzntError> {
    let start = out.len();
    let mut at = 0usize;
    while at < packed.len() && out.len() < limit {
        let flags = packed[at];
        at += 1;
        for bit in 0..8 {
            if at >= packed.len() || out.len() >= limit { break; }
            if out.len() - start > LZNT_CHUNK_SIZE { return Err(LzntError::Overrun); }
            if flags & (1 << bit) == 0 {
                out.push(packed[at]);
                at += 1;
                continue;
            }
            if at + 1 >= packed.len() { return Err(LzntError::Truncated); }
            let pair = u16::from_le_bytes([packed[at], packed[at + 1]]);
            at += 2;
            let index = window_index(out.len() - start);
            let (offset, mut length) = parse_pair(pair, index);
            if offset > out.len() - start { return Err(LzntError::BadReference); }
            if out.len() + length > limit { length = limit - out.len(); }
            // Byte at a time, and deliberately: a match may overlap what it is
            // producing, which is how a run of one byte is encoded.
            for _ in 0..length {
                let byte = out[out.len() - offset];
                out.push(byte);
            }
        }
    }
    Ok(out.len() - start)
}

/// Decompress a whole stream into at most `unc_size` bytes.
///
/// A stream that ends before filling the buffer leaves the rest ZERO, which is
/// what a compressed unit shorter than its uncompressed length means.
/// # C: O(compressed bytes)
pub fn decompress(packed: &[u8], unc_size: usize) -> Result<Vec<u8>, LzntError> {
    let mut out: Vec<u8> = Vec::with_capacity(unc_size);
    let mut at = 0usize;
    while at + CHUNK_HEADER_BYTES <= packed.len() && out.len() < unc_size {
        let header = u16::from_le_bytes([packed[at], packed[at + 1]]);
        // A header of zero ends the stream: the rest of the unit was never
        // written.
        if header == 0 { break; }
        let packed_len = CHUNK_HEADER_BYTES + 1 + usize::from(header & CHUNK_LENGTH_MASK);
        if at + packed_len > packed.len() { return Err(LzntError::Truncated); }
        let body = &packed[at + CHUNK_HEADER_BYTES..at + packed_len];
        let produced = if header & CHUNK_COMPRESSED != 0 {
            chunk(&mut out, unc_size, body)?
        } else {
            let take = core::cmp::min(body.len(), unc_size - out.len());
            out.extend_from_slice(&body[..take]);
            take
        };
        at += packed_len;
        // A chunk that produced less than a whole chunk and is not the last
        // one is followed by zeros to the chunk boundary.
        if produced < LZNT_CHUNK_SIZE && out.len() < unc_size && at + 1 < packed.len() {
            let pad = core::cmp::min(LZNT_CHUNK_SIZE - produced, unc_size - out.len());
            out.resize(out.len() + pad, 0);
        }
    }
    out.resize(unc_size, 0);
    Ok(out)
}

/// Compress one chunk, or report that it does not compress.
///
/// `None` means the chunk grew, which is the case the format handles by
/// storing the chunk whole — an implementation that compresses regardless
/// writes a unit larger than the space it saved.
/// # C: O(chunk bytes * window)
fn compress_chunk(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0usize;
    while at < data.len() {
        let mut flags = 0u8;
        let flags_at = out.len();
        out.push(0);
        for bit in 0..8 {
            if at >= data.len() { break; }
            let index = window_index(at);
            let window = MAX_OFFSETS[index];
            let max_len = (1usize << (12 - index)) - 1 + MIN_MATCH;
            let mut best = (0usize, 0usize);
            let from = at.saturating_sub(window);
            for back in from..at {
                let mut len = 0usize;
                while at + len < data.len() && len < max_len
                    && data[back + len % (at - back)] == data[at + len] { len += 1; }
                if len > best.1 { best = (at - back, len); }
            }
            if best.1 >= MIN_MATCH {
                let pair = make_pair(best.0, best.1, index);
                out.extend_from_slice(&pair.to_le_bytes());
                flags |= 1 << bit;
                at += best.1;
            } else {
                out.push(data[at]);
                at += 1;
            }
            if out.len() >= data.len() { return None; }
        }
        out[flags_at] = flags;
    }
    if out.len() >= data.len() { return None; }
    Some(out)
}

/// Compress a stream into the chunked form an attribute stores.
///
/// A chunk that does not compress is stored whole with its header saying so,
/// which is what keeps a compressed file that holds incompressible data no
/// larger than the data.
/// # C: O(bytes * window)
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in data.chunks(LZNT_CHUNK_SIZE) {
        match compress_chunk(piece) {
            Some(packed) => {
                let header = CHUNK_COMPRESSED | ((packed.len() - 1) as u16 & CHUNK_LENGTH_MASK);
                out.extend_from_slice(&header.to_le_bytes());
                out.extend_from_slice(&packed);
            }
            None => {
                let header = (piece.len() - 1) as u16 & CHUNK_LENGTH_MASK;
                out.extend_from_slice(&header.to_le_bytes());
                out.extend_from_slice(piece);
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/lznt.rs"]
mod tests;
