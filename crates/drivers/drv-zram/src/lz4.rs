//! Safe LZ4-fast encoder with Linux zram acceleration semantics.

use alloc::vec::Vec;

/// LZ4 match minimum defined by the block format.
const MIN_MATCH: usize = 4;
/// LZ4 requires its final bytes to be literals.
const LAST_LITERALS: usize = 5;
/// Reference LZ4's match-finder safety margin.
const MATCH_FIND_LIMIT: usize = 12;
/// LZ4 block offsets are unsigned 16-bit values.
const MAX_DISTANCE: usize = u16::MAX as usize;
/// Reference LZ4 uses a 64 Ki-entry hash table for its fast compressor.
const HASH_BITS: usize = 16;
const HASH_ENTRIES: usize = 1 << HASH_BITS;
/// Reference LZ4 increases its probe stride every 32 unsuccessful probes.
const SKIP_TRIGGER: usize = 5;
/// No input position has this table value.
const NONE: usize = usize::MAX;

/// Normalize Linux `LZ4_compress_fast`'s signed acceleration argument.
/// Linux treats every value below one as `LZ4_ACCELERATION_DEFAULT` (one).
/// # C: O(1)
fn acceleration(level: i32) -> usize { usize::try_from(level).ok().filter(|level| *level > 0).unwrap_or(1) }

/// Hash the four-byte sequence at `at`, matching LZ4's one-candidate fast
/// matcher rather than performing a separate high-compression search.
/// # C: O(1)
fn hash(bytes: &[u8], at: usize) -> usize {
    let word = u32::from_le_bytes(bytes[at..at + MIN_MATCH].try_into().expect("lz4 match window"));
    ((word.wrapping_mul(2_654_435_761) >> (u32::BITS - HASH_BITS as u32)) as usize) & (HASH_ENTRIES - 1)
}

/// Append LZ4's variable-length extension bytes after a saturated nibble.
/// # C: O(length / 255)
fn append_length(out: &mut Vec<u8>, mut length: usize) {
    while length >= u8::MAX as usize { out.push(u8::MAX); length -= u8::MAX as usize; }
    out.push(length as u8);
}

/// Append the terminal literal-only sequence required by the LZ4 format.
/// # C: O(literal bytes)
fn emit_last_literals(out: &mut Vec<u8>, source: &[u8], start: usize) {
    let length = source.len() - start;
    let token = (core::cmp::min(length, 15) as u8) << 4;
    out.push(token);
    if length >= 15 { append_length(out, length - 15); }
    out.extend_from_slice(&source[start..]);
}

/// Append one LZ4 literal/match sequence.
/// # C: O(literal bytes + match-length extension)
fn emit_sequence(out: &mut Vec<u8>, source: &[u8], literal_start: usize,
    match_start: usize, offset: usize, match_length: usize) {
    let literals = match_start - literal_start;
    let encoded_match = match_length - MIN_MATCH;
    let token = ((core::cmp::min(literals, 15) as u8) << 4) | core::cmp::min(encoded_match, 15) as u8;
    out.push(token);
    if literals >= 15 { append_length(out, literals - 15); }
    out.extend_from_slice(&source[literal_start..match_start]);
    out.extend_from_slice(&(offset as u16).to_le_bytes());
    if encoded_match >= 15 { append_length(out, encoded_match - 15); }
}

/// Compress one LZ4 block with Linux `LZ4_compress_fast`-style acceleration.
/// The output is ordinary LZ4 block data and is decoded by the existing
/// `lz4_flex::block::{decompress_into,decompress_into_with_dict}` paths.
///
/// This is deliberately a fast one-candidate hash matcher: acceleration raises
/// the unsuccessful-search stride, so it changes the actual match discovery
/// and therefore the emitted compressed representation without altering the
/// LZ4 wire contract. External dictionaries are trimmed to Linux LZ4's 64 KiB
/// history window and are never copied into the emitted block.
/// # C: O(input bytes / acceleration + dictionary bytes)
pub(crate) fn compress(input: &[u8], dictionary: &[u8], level: i32) -> Vec<u8> {
    if input.len() < MATCH_FIND_LIMIT { return literal_block(input); }
    let dictionary = if dictionary.len() > MAX_DISTANCE { &dictionary[dictionary.len() - MAX_DISTANCE..] } else { dictionary };
    let history = dictionary.len();
    let mut source = Vec::with_capacity(history + input.len());
    source.extend_from_slice(dictionary);
    source.extend_from_slice(input);
    let end = source.len();
    let last_match_start = end - MATCH_FIND_LIMIT;
    let mut table = alloc::vec![NONE; HASH_ENTRIES];
    for at in 0..history.saturating_sub(MIN_MATCH - 1) { table[hash(&source, at)] = at; }
    let mut out = Vec::with_capacity(input.len());
    let mut anchor = history;
    let mut next = history;
    let accel = acceleration(level);
    let mut skipped = accel.saturating_mul(1 << SKIP_TRIGGER);

    while next <= last_match_start {
        let current = next;
        let candidate = table[hash(&source, current)];
        table[hash(&source, current)] = current;
        if candidate != NONE && current - candidate <= MAX_DISTANCE
            && source[candidate..candidate + MIN_MATCH] == source[current..current + MIN_MATCH] {
            let mut match_start = current;
            let mut candidate_start = candidate;
            while match_start > anchor && candidate_start > 0
                && source[match_start - 1] == source[candidate_start - 1] {
                match_start -= 1;
                candidate_start -= 1;
            }
            let candidate_limit = if candidate_start < history { history } else { end };
            let mut match_length = MIN_MATCH;
            while match_start + match_length < end - LAST_LITERALS
                && candidate_start + match_length < candidate_limit
                && source[match_start + match_length] == source[candidate_start + match_length] {
                match_length += 1;
            }
            emit_sequence(&mut out, &source, anchor, match_start, match_start - candidate_start, match_length);
            let after = match_start + match_length;
            for at in match_start + 1..after {
                if at <= last_match_start { table[hash(&source, at)] = at; }
            }
            anchor = after;
            next = after;
            skipped = accel.saturating_mul(1 << SKIP_TRIGGER);
            continue;
        }
        let step = core::cmp::max(skipped >> SKIP_TRIGGER, 1);
        skipped = skipped.saturating_add(1);
        next = current.saturating_add(step);
    }
    emit_last_literals(&mut out, &source, anchor);
    out
}

/// Render a valid literal-only LZ4 block for small unmatchable inputs.
/// # C: O(input bytes)
fn literal_block(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 1);
    emit_last_literals(&mut out, input, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCELERATION_ONE: i32 = 1;
    const ACCELERATION_TWO: i32 = 2;
    const ACCELERATION_EIGHT: i32 = 8;
    const ACCELERATION_MAXIMUM: i32 = i32::MAX;
    const DICTIONARY: &[u8] = b"ABCDEFGH";
    const INPUT: &[u8] = b"qrABCDEFGH0123456789abcdefghijklmnopqrstuv";
    const PAGE_BYTES: usize = 4096;
    const PATTERN_BYTES: usize = 37;
    const PATTERN_FACTOR: usize = 13;
    const ACCELERATIONS: &[i32] = &[ACCELERATION_ONE, ACCELERATION_TWO, ACCELERATION_EIGHT, ACCELERATION_MAXIMUM];

    #[test]
    fn acceleration_changes_match_discovery_but_preserves_lz4_decoding() {
        let fast = compress(INPUT, DICTIONARY, ACCELERATION_EIGHT);
        let default = compress(INPUT, DICTIONARY, ACCELERATION_ONE);
        assert_ne!(default, fast, "acceleration must affect emitted LZ4 matches");
        let mut restored = [0u8; INPUT.len()];
        let written = lz4_flex::block::decompress_into_with_dict(&default, &mut restored, DICTIONARY).unwrap();
        assert_eq!(written, INPUT.len());
        assert_eq!(&restored, INPUT);
        let written = lz4_flex::block::decompress_into_with_dict(&fast, &mut restored, DICTIONARY).unwrap();
        assert_eq!(written, INPUT.len());
        assert_eq!(&restored, INPUT);
    }

    #[test]
    fn nonpositive_linux_acceleration_uses_default() {
        assert_eq!(compress(INPUT, DICTIONARY, 0), compress(INPUT, DICTIONARY, ACCELERATION_ONE));
        assert_eq!(compress(INPUT, DICTIONARY, -1), compress(INPUT, DICTIONARY, ACCELERATION_ONE));
    }

    #[test]
    fn every_supported_acceleration_roundtrips_a_zram_sized_block() {
        let mut input = [0u8; PAGE_BYTES];
        for (index, byte) in input.iter_mut().enumerate() { *byte = (index % PATTERN_BYTES * PATTERN_FACTOR) as u8; }
        for &level in ACCELERATIONS {
            let packed = compress(&input, DICTIONARY, level);
            let mut restored = [0u8; PAGE_BYTES];
            assert_eq!(lz4_flex::block::decompress_into_with_dict(&packed, &mut restored, DICTIONARY).unwrap(), PAGE_BYTES);
            assert_eq!(restored, input);
        }
    }
}
