//! Linux zcomp LZ4-HC raw-block encoder with bounded hash-chain search.

use alloc::vec;
use alloc::vec::Vec;

/// LZ4 block-format minimum back-reference length.
const MIN_MATCH_BYTES: usize = 4;
/// LZ4 reserves its final five bytes for literals.
const LAST_LITERAL_BYTES: usize = 5;
/// LZ4's match finder needs a twelve-byte readable window.
const MATCH_FIND_LIMIT: usize = 12;
/// LZ4 block offsets have unsigned 16-bit range.
const MAX_DISTANCE_BYTES: usize = u16::MAX as usize;
/// Linux LZ4-HC's default compression level.
const DEFAULT_LEVEL: i32 = 9;
/// Linux LZ4-HC's accepted compression-level bounds.
const MIN_LEVEL: i32 = 1;
const MAX_LEVEL: i32 = 12;
/// One 16-bit hash entry per four-byte prefix, matching LZ4's table width.
const HASH_BITS: usize = 16;
const HASH_ENTRIES: usize = 1 << HASH_BITS;
/// No source position occupies this hash-chain link.
const NONE: usize = usize::MAX;
/// LZ4's multiplicative hash constant for a four-byte little-endian word.
const HASH_MULTIPLIER: u32 = 2_654_435_761;

/// Clamp Linux LZ4-HC's requested level before deriving match attempts.
/// # C: O(1)
fn level(value: i32) -> i32 {
    if value < MIN_LEVEL { DEFAULT_LEVEL } else { value.min(MAX_LEVEL) }
}

/// Linux uses `1 << (compressionLevel - 1)` HC match attempts. # C: O(1)
fn attempts(value: i32) -> usize { 1usize << (level(value) - MIN_LEVEL) as u32 }

/// Hash a four-byte LZ4 candidate window. # C: O(1)
fn hash(bytes: &[u8], at: usize) -> usize {
    let word = u32::from_le_bytes(bytes[at..at + MIN_MATCH_BYTES].try_into().expect("lz4hc match window"));
    ((word.wrapping_mul(HASH_MULTIPLIER) >> (u32::BITS - HASH_BITS as u32)) as usize) & (HASH_ENTRIES - 1)
}

/// Append LZ4's extended-length bytes. # C: O(length / 255)
fn append_length(out: &mut Vec<u8>, mut length: usize) {
    while length >= u8::MAX as usize { out.push(u8::MAX); length -= u8::MAX as usize; }
    out.push(length as u8);
}

/// Emit the required trailing literal-only LZ4 sequence. # C: O(literal bytes)
fn emit_last_literals(out: &mut Vec<u8>, source: &[u8], start: usize) {
    let length = source.len() - start;
    out.push((core::cmp::min(length, 15) as u8) << 4);
    if length >= 15 { append_length(out, length - 15); }
    out.extend_from_slice(&source[start..]);
}

/// Emit one LZ4 literal/match sequence. # C: O(literal bytes + extensions)
fn emit_sequence(out: &mut Vec<u8>, source: &[u8], anchor: usize, at: usize, offset: usize, length: usize) {
    let literals = at - anchor;
    let encoded = length - MIN_MATCH_BYTES;
    out.push(((core::cmp::min(literals, 15) as u8) << 4) | core::cmp::min(encoded, 15) as u8);
    if literals >= 15 { append_length(out, literals - 15); }
    out.extend_from_slice(&source[anchor..at]);
    out.extend_from_slice(&(offset as u16).to_le_bytes());
    if encoded >= 15 { append_length(out, encoded - 15); }
}

/// Insert one position into its reusable HC hash chain. # C: O(1)
fn insert(source: &[u8], at: usize, heads: &mut [usize], previous: &mut [usize]) {
    if at + MIN_MATCH_BYTES > source.len() { return; }
    let bucket = hash(source, at);
    previous[at] = heads[bucket];
    heads[bucket] = at;
}

/// Find the longest valid candidate among Linux-level-bounded HC probes.
/// # C: O(match attempts × match length)
fn best_match(source: &[u8], at: usize, history: usize, heads: &[usize], previous: &[usize], limit: usize) -> Option<(usize, usize)> {
    if at + MIN_MATCH_BYTES > source.len() { return None; }
    let mut candidate = heads[hash(source, at)];
    let mut probes = 0usize;
    let mut best = (0usize, 0usize);
    while candidate != NONE && probes < limit {
        let distance = at - candidate;
        if distance > MAX_DISTANCE_BYTES { break; }
        if source[candidate..candidate + MIN_MATCH_BYTES] == source[at..at + MIN_MATCH_BYTES] {
            let candidate_end = if candidate < history { history } else { source.len() };
            let mut length = MIN_MATCH_BYTES;
            while at + length < source.len() - LAST_LITERAL_BYTES && candidate + length < candidate_end
                && source[candidate + length] == source[at + length] { length += 1; }
            if length > best.0 { best = (length, distance); }
        }
        candidate = previous[candidate];
        probes += 1;
    }
    (best.0 >= MIN_MATCH_BYTES).then_some(best)
}

/// Compress one raw LZ4 block with Linux LZ4-HC level semantics. Output is
/// ordinary LZ4 block data and uses the configured generic zcomp dictionary.
/// # C: O(page bytes × level-bounded match search)
pub(crate) fn compress(input: &[u8], dictionary: &[u8], compression_level: i32) -> Vec<u8> {
    if input.len() < MATCH_FIND_LIMIT { let mut out = Vec::with_capacity(input.len() + 1); emit_last_literals(&mut out, input, 0); return out; }
    let dictionary = if dictionary.len() > MAX_DISTANCE_BYTES { &dictionary[dictionary.len() - MAX_DISTANCE_BYTES..] } else { dictionary };
    let history = dictionary.len();
    let mut source = Vec::with_capacity(history + input.len());
    source.extend_from_slice(dictionary);
    source.extend_from_slice(input);
    let last_match_start = source.len() - MATCH_FIND_LIMIT;
    let mut heads = vec![NONE; HASH_ENTRIES];
    let mut previous = vec![NONE; source.len()];
    for at in 0..history.saturating_sub(MIN_MATCH_BYTES - 1) { insert(&source, at, &mut heads, &mut previous); }
    let mut out = Vec::with_capacity(input.len());
    let mut anchor = history;
    let mut at = history;
    let limit = attempts(compression_level);
    while at <= last_match_start {
        let found = best_match(&source, at, history, &heads, &previous, limit);
        insert(&source, at, &mut heads, &mut previous);
        let Some((length, offset)) = found else { at += 1; continue; };
        emit_sequence(&mut out, &source, anchor, at, offset, length);
        let after = at + length;
        for position in at + 1..after { insert(&source, position, &mut heads, &mut previous); }
        anchor = after;
        at = after;
    }
    emit_last_literals(&mut out, &source, anchor);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_BYTES: usize = 4096;
    const LOW_LEVEL: i32 = 1;
    const HIGH_LEVEL: i32 = 12;
    const PATTERN_BYTES: usize = 97;
    const FACTOR: usize = 31;

    #[test]
    fn levels_clamp_like_linux_lz4hc() {
        assert_eq!(level(0), DEFAULT_LEVEL);
        assert_eq!(level(-1), DEFAULT_LEVEL);
        assert_eq!(level(MAX_LEVEL + 1), MAX_LEVEL);
        assert!(attempts(HIGH_LEVEL) > attempts(LOW_LEVEL));
    }

    #[test]
    fn all_linux_levels_emit_decodable_raw_lz4() {
        let mut page = [0u8; PAGE_BYTES];
        for (index, byte) in page.iter_mut().enumerate() { *byte = ((index % PATTERN_BYTES) * FACTOR) as u8; }
        for value in MIN_LEVEL..=MAX_LEVEL {
            let packed = compress(&page, &[], value);
            let mut decoded = [0u8; PAGE_BYTES];
            assert_eq!(lz4_flex::block::decompress_into(&packed, &mut decoded).unwrap(), PAGE_BYTES);
            assert_eq!(decoded, page);
        }
    }
}
