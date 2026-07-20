//! Raw RFC1951 fixed-Huffman compressor with a configured history window.

use alloc::vec::Vec;

use block::{BlockError, KResult};

/// Linux zram's deflate backend default (`backend_deflate.c`).
pub(super) const PARAM_NOT_SET: i32 = i32::MIN;
pub(super) const DEFAULT_COMPRESSION_LEVEL: i32 = -1;
pub(super) const DEFAULT_WINDOW_BITS: i32 = -11;
const MIN_WINDOW_BITS: i32 = -15;
const MAX_WINDOW_BITS: i32 = -8;
const MIN_COMPRESSION_LEVEL: i32 = -1;
const MAX_COMPRESSION_LEVEL: i32 = 9;
const MIN_MATCH_BYTES: usize = 3;
const MAX_MATCH_BYTES: usize = 258;
const HASH_BITS: usize = 12;
const HASH_ENTRIES: usize = 1 << HASH_BITS;
const HASH_MASK: usize = HASH_ENTRIES - 1;
const NO_POSITION: usize = usize::MAX;
const MAX_MATCH_CANDIDATES: usize = 64;
const LENGTH_BASE: [usize; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE: [usize; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DISTANCE_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// Validate the raw zlib window range consumed by Linux's zram backend.
/// # C: O(1)
fn configured_window_bits(bits: i32) -> KResult<i8> {
    let bits = if bits == PARAM_NOT_SET { DEFAULT_WINDOW_BITS } else { bits };
    if !(MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&bits) { return Err(BlockError::Einval); }
    i8::try_from(bits).map_err(|_| BlockError::Einval)
}

fn configured_level(level: i32) -> KResult<i32> {
    let level = if level == PARAM_NOT_SET { DEFAULT_COMPRESSION_LEVEL } else { level };
    if (MIN_COMPRESSION_LEVEL..=MAX_COMPRESSION_LEVEL).contains(&level) { Ok(level) }
    else { Err(BlockError::Einval) }
}

/// Validate the parameters consumed by Linux's deflate backend during zram
/// initialization, after generic sysfs parsing has stored its signed values.
/// # C: O(1)
pub(super) fn validate_initialization(level: i32, bits: i32) -> KResult<()> {
    configured_level(level)?;
    configured_window_bits(bits)?;
    Ok(())
}

struct Bits { out: Vec<u8>, value: u32, count: u8 }

impl Bits {
    fn new() -> Self { Self { out: Vec::new(), value: 0, count: 0 } }
    fn put(&mut self, value: u16, count: u8) {
        self.value |= u32::from(value) << self.count;
        self.count += count;
        while self.count >= u8::BITS as u8 {
            self.out.push(self.value as u8);
            self.value >>= u8::BITS;
            self.count -= u8::BITS as u8;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.count != 0 { self.out.push(self.value as u8); }
        self.out
    }
}

fn reverse(value: u16, count: u8) -> u16 { value.reverse_bits() >> (u16::BITS as u8 - count) }

fn literal(bits: &mut Bits, value: u16) {
    let (code, count) = match value {
        0..=143 => (value + 0x30, 8), 144..=255 => (value - 144 + 0x190, 9),
        256..=279 => (value - 256, 7), _ => (value - 280 + 0xc0, 8),
    };
    bits.put(reverse(code, count), count);
}

fn table_code(value: usize, base: &[usize], extra: &[u8]) -> KResult<(usize, usize, u8)> {
    let index = base.iter().rposition(|candidate| *candidate <= value).ok_or(BlockError::Einval)?;
    Ok((index, value - base[index], extra[index]))
}

fn emit_match(bits: &mut Bits, length: usize, distance: usize) -> KResult<()> {
    let (length_code, length_extra, length_bits) = table_code(length, &LENGTH_BASE, &LENGTH_EXTRA)?;
    literal(bits, (257 + length_code) as u16);
    bits.put(length_extra as u16, length_bits);
    let (distance_code, distance_extra, distance_bits) = table_code(distance, &DISTANCE_BASE, &DISTANCE_EXTRA)?;
    bits.put(reverse(distance_code as u16, 5), 5);
    bits.put(distance_extra as u16, distance_bits);
    Ok(())
}

fn hash(bytes: &[u8], at: usize) -> usize {
    ((usize::from(bytes[at]) << 8) ^ (usize::from(bytes[at + 1]) << 4) ^ usize::from(bytes[at + 2])) & HASH_MASK
}

fn remember(bytes: &[u8], at: usize, heads: &mut [usize; HASH_ENTRIES], previous: &mut [usize]) {
    if at + MIN_MATCH_BYTES > bytes.len() { return; }
    let slot = hash(bytes, at);
    previous[at] = heads[slot];
    heads[slot] = at;
}

fn best_match(bytes: &[u8], at: usize, window: usize, heads: &[usize; HASH_ENTRIES], previous: &[usize]) -> Option<(usize, usize)> {
    if at + MIN_MATCH_BYTES > bytes.len() { return None; }
    let mut candidate = heads[hash(bytes, at)];
    let mut probes = 0;
    let mut best = (0, 0);
    while candidate != NO_POSITION && probes < MAX_MATCH_CANDIDATES {
        let distance = at - candidate;
        if distance > window { break; }
        let limit = (bytes.len() - at).min(MAX_MATCH_BYTES);
        let mut length = 0;
        while length < limit && bytes[candidate + length] == bytes[at + length] { length += 1; }
        if length > best.0 { best = (length, distance); if length == limit { break; } }
        candidate = previous[candidate];
        probes += 1;
    }
    (best.0 >= MIN_MATCH_BYTES).then_some(best)
}

/// Compress one zram page as one final fixed-Huffman raw-deflate block.
/// # C: O(page bytes × bounded match probes)
pub(super) fn compress(bytes: &[u8], level: i32, window_bits: i32) -> KResult<Vec<u8>> {
    let level = configured_level(level)?;
    let window_bits = configured_window_bits(window_bits)?;
    let shift = u32::try_from(-i16::from(window_bits)).map_err(|_| BlockError::Einval)?;
    let window = 1usize.checked_shl(shift).ok_or(BlockError::Einval)?;
    let mut bits = Bits::new();
    // BFINAL=1, BTYPE=fixed (01), written least-significant-bit first.
    bits.put(0b011, 3);
    let mut heads = [NO_POSITION; HASH_ENTRIES];
    let mut previous = alloc::vec![NO_POSITION; bytes.len()];
    let mut at = 0;
    while at < bytes.len() {
        if level != 0 {
            if let Some((length, distance)) = best_match(bytes, at, window, &heads, &previous) {
                emit_match(&mut bits, length, distance)?;
                for index in at..at + length { remember(bytes, index, &mut heads, &mut previous); }
                at += length;
                continue;
            }
        }
        literal(&mut bits, u16::from(bytes[at]));
        remember(bytes, at, &mut heads, &mut previous);
        at += 1;
    }
    literal(&mut bits, 256);
    Ok(bits.finish())
}
