// Huff0 literal decoding (RFC 8878 4.2).
//
// The weight of a symbol is `maxBits + 1 - codeLength`, so a bigger weight is a
// SHORTER code. Weights are transmitted either as 4-bit nibbles or, more often,
// FSE-compressed with two interleaved states. The LAST symbol's weight is never
// transmitted: it is whatever makes the code complete, which is also the check
// that the table is well formed.
//
// The decode table is flat and indexed by `maxBits` peeked bits: a symbol with
// an `n`-bit code owns `1 << (maxBits - n)` consecutive slots, so one lookup
// gives both the symbol and how many bits it actually cost.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::bits::RevReader;
use crate::fse;
use crate::uapi::{ACCURACY_LOG_MAX_HUFF, HUFF_MAX_BITS, HUFF_MAX_SYMBOLS};
use crate::{Error, Result};

/// Header byte at or above this means the weights are listed directly, one
/// nibble each, rather than FSE-compressed.
const DIRECT_WEIGHTS_THRESHOLD: u8 = 128;
/// Symbol count encoded by a direct header byte is `byte - 127`.
const DIRECT_WEIGHTS_BIAS: u8 = 127;

#[derive(Copy, Clone, Default, Debug)]
struct Slot {
    symbol: u8,
    nb_bits: u8,
}

#[derive(Debug)]
pub struct Table {
    max_bits: u32,
    slots: Vec<Slot>,
}

impl Table {
    /// Parse a weight header and build the decode table. Returns the table and
    /// the bytes the header consumed.
    /// # C: O(2^max_bits)
    pub fn parse(src: &[u8]) -> Result<(Self, usize)> {
        let Some((&header, rest)) = src.split_first() else { return Err(Error::Truncated) };
        let (weights, used) = if header >= DIRECT_WEIGHTS_THRESHOLD {
            let n = (header - DIRECT_WEIGHTS_BIAS) as usize;
            let bytes = n.div_ceil(2);
            if rest.len() < bytes { return Err(Error::Truncated); }
            let mut w = Vec::with_capacity(n);
            for i in 0..n {
                // High nibble first, matching the order symbols are numbered.
                let byte = rest[i / 2];
                w.push(if i % 2 == 0 { byte >> 4 } else { byte & 0x0F });
            }
            (w, 1 + bytes)
        } else {
            let bytes = header as usize;
            if rest.len() < bytes { return Err(Error::Truncated); }
            (decode_fse_weights(&rest[..bytes])?, 1 + bytes)
        };
        Ok((Self::from_weights(&weights)?, used))
    }

    /// Build from explicit weights, inferring the final symbol's weight.
    /// # C: O(2^max_bits)
    fn from_weights(weights: &[u8]) -> Result<Self> {
        if weights.is_empty() || weights.len() >= HUFF_MAX_SYMBOLS {
            return Err(Error::BadHuffmanTable);
        }
        // Each weight w > 0 costs 2^(w-1) of the code space.
        let mut total: u32 = 0;
        for &w in weights {
            if w as u32 > HUFF_MAX_BITS { return Err(Error::BadHuffmanTable); }
            if w > 0 { total += 1 << (w - 1); }
        }
        if total == 0 { return Err(Error::BadHuffmanTable); }
        let max_bits = 32 - total.leading_zeros();
        if max_bits > HUFF_MAX_BITS { return Err(Error::BadHuffmanTable); }
        let size = 1u32 << max_bits;
        // Whatever code space is left belongs to the untransmitted last symbol,
        // and it must be exactly one power of two or the code is incomplete.
        let left = size - total;
        // `left` is never zero here -- `max_bits` is one above the top set bit
        // of `total` -- so the real check is that it is a single power of two,
        // i.e. exactly one symbol's worth of code space.
        if !left.is_power_of_two() { return Err(Error::BadHuffmanTable); }
        let last = left.trailing_zeros() + 1;
        if last > HUFF_MAX_BITS { return Err(Error::BadHuffmanTable); }

        let mut all: Vec<u8> = Vec::with_capacity(weights.len() + 1);
        all.extend_from_slice(weights);
        all.push(last as u8);

        // Canonical order: ASCENDING weight -- so the LONGEST codes occupy the
        // low slots -- with ties broken by symbol number. Reversing this still
        // produces a valid prefix code, just a different one, so a stream
        // decodes into a permuted alphabet rather than failing. That is the
        // shape the reference-conformance test caught.
        let mut slots = vec![Slot::default(); size as usize];
        let mut at = 0usize;
        for w in 1..=max_bits {
            let nb_bits = max_bits + 1 - w;
            let run = 1usize << (w - 1);
            for (sym, &sw) in all.iter().enumerate() {
                if sw as u32 != w { continue; }
                for _ in 0..run {
                    slots[at] = Slot { symbol: sym as u8, nb_bits: nb_bits as u8 };
                    at += 1;
                }
            }
        }
        if at != size as usize { return Err(Error::BadHuffmanTable); }
        Ok(Self { max_bits, slots })
    }

    /// Decode exactly `n` symbols from one bitstream.
    /// # C: O(n)
    pub fn decode_stream(&self, src: &[u8], n: usize, out: &mut Vec<u8>) -> Result<()> {
        let mut r = RevReader::new(src)?;
        for _ in 0..n {
            let idx = r.peek(self.max_bits) as usize;
            let slot = self.slots[idx];
            r.consume(slot.nb_bits as u32);
            out.push(slot.symbol);
        }
        if r.overran() { return Err(Error::BitstreamOverrun); }
        Ok(())
    }

    /// Decode the four-stream form: a 6-byte jump table then four bitstreams,
    /// each covering a quarter of the output.
    /// # C: O(n)
    pub fn decode_4streams(&self, src: &[u8], n: usize, out: &mut Vec<u8>) -> Result<()> {
        const JUMP_TABLE_LEN: usize = 6;
        if src.len() < JUMP_TABLE_LEN { return Err(Error::Truncated); }
        let s1 = u16::from_le_bytes([src[0], src[1]]) as usize;
        let s2 = u16::from_le_bytes([src[2], src[3]]) as usize;
        let s3 = u16::from_le_bytes([src[4], src[5]]) as usize;
        let body = &src[JUMP_TABLE_LEN..];
        let total = s1 + s2 + s3;
        if total > body.len() { return Err(Error::Truncated); }
        // The last stream's size is whatever remains; only the first three are
        // transmitted.
        let quarters = [
            &body[..s1],
            &body[s1..s1 + s2],
            &body[s1 + s2..total],
            &body[total..],
        ];
        // The first three streams decode `ceil(n/4)` symbols each; the fourth
        // takes the remainder, which is why an `n` not divisible by four still
        // decodes exactly.
        let per = n.div_ceil(4);
        if per * 3 > n { return Err(Error::BadHuffmanTable); }
        let counts = [per, per, per, n - per * 3];
        for (stream, count) in quarters.iter().zip(counts) {
            self.decode_stream(stream, count, out)?;
        }
        Ok(())
    }
}

/// Decode FSE-compressed weights: one table description followed by a bitstream
/// with two interleaved states.
/// # C: O(weights)
fn decode_fse_weights(src: &[u8]) -> Result<Vec<u8>> {
    // Weights are 0..=HUFF_MAX_BITS, so the table's symbol space is small.
    let (norm, log, used) = fse::read_distribution(src, HUFF_MAX_BITS as u8,
        ACCURACY_LOG_MAX_HUFF)?;
    let table = fse::Table::from_normalized(&norm, log)?;
    if used >= src.len() { return Err(Error::Truncated); }
    let mut r = RevReader::new(&src[used..])?;
    let mut states = [fse::Decoder::init(&table, &mut r)?, fse::Decoder::init(&table, &mut r)?];

    let mut weights = Vec::new();
    // The two states take turns: decode with one, advance it, and stop the
    // moment an advance walks off the bottom of the stream -- at which point
    // the OTHER state still holds one undelivered symbol, which is the final
    // weight. The transmitted list is one short of the alphabet; the last
    // symbol's weight is inferred from the leftover code space.
    loop {
        push_weight(&mut weights, states[0].peek())?;
        states[0].advance(&mut r)?;
        if r.remaining() <= -1 {
            push_weight(&mut weights, states[1].peek())?;
            break;
        }
        push_weight(&mut weights, states[1].peek())?;
        states[1].advance(&mut r)?;
        if r.remaining() <= -1 {
            push_weight(&mut weights, states[0].peek())?;
            break;
        }
    }
    Ok(weights)
}

/// The final symbol's weight is inferred, so at most 255 are transmitted.
const MAX_TRANSMITTED_WEIGHTS: usize = HUFF_MAX_SYMBOLS - 1;

fn push_weight(weights: &mut Vec<u8>, w: u8) -> Result<()> {
    if weights.len() >= MAX_TRANSMITTED_WEIGHTS { return Err(Error::BadHuffmanTable); }
    if w as u32 > HUFF_MAX_BITS { return Err(Error::BadHuffmanTable); }
    weights.push(w);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flat_eight_symbol_code_gives_every_symbol_three_bits() {
        // Eight symbols of equal weight: seven transmitted, the eighth inferred.
        let t = Table::from_weights(&[1, 1, 1, 1, 1, 1, 1]).unwrap();
        assert_eq!(t.max_bits, 3);
        assert_eq!(t.slots.len(), 8);
        for (i, s) in t.slots.iter().enumerate() {
            assert_eq!(s.nb_bits, 3);
            assert_eq!(s.symbol, i as u8, "a flat code is the identity");
        }
    }

    #[test]
    fn longer_codes_take_the_low_slots_and_shorter_ones_the_high_slots() {
        // Weights 2,1,1: symbol 0 has a 1-bit code, symbols 1 and 2 have 2-bit
        // codes. zstd's canonical layout puts the LONG codes first, so symbol 0
        // owns the top half. The mirror layout is also a valid prefix code,
        // which is why getting this backwards decodes into a permuted alphabet
        // instead of an error.
        let t = Table::from_weights(&[2, 1]).unwrap();
        assert_eq!(t.max_bits, 2);
        assert_eq!(t.slots.len(), 4);
        assert_eq!((t.slots[0].symbol, t.slots[0].nb_bits), (1, 2));
        assert_eq!((t.slots[1].symbol, t.slots[1].nb_bits), (2, 2));
        assert_eq!((t.slots[2].symbol, t.slots[2].nb_bits), (0, 1));
        assert_eq!((t.slots[3].symbol, t.slots[3].nb_bits), (0, 1));
    }

    #[test]
    fn an_incomplete_code_is_rejected() {
        // Weights 3 and 1 use 4/8 + 1/8, leaving 3/8 -- not a power of two, so
        // no single final symbol can complete the code.
        assert_eq!(Table::from_weights(&[3, 1]).unwrap_err(), Error::BadHuffmanTable);
        // Three maximum-weight symbols need a 12-bit code, one past the
        // format's ceiling.
        assert_eq!(Table::from_weights(&[11, 11, 11]).unwrap_err(),
            Error::BadHuffmanTable);
    }

    #[test]
    fn direct_weights_read_high_nibble_first() {
        // Header 127+2 = two weights, one byte: 0x21 -> weights 2 then 1.
        let (t, used) = Table::parse(&[129, 0x21]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(t.max_bits, 2);
        assert_eq!(t.slots[0].symbol, 1, "the longest code takes the low slots");
        assert_eq!(t.slots[3].symbol, 0, "weight 2 is the shortest code");
    }

    #[test]
    fn a_truncated_weight_header_is_not_read_past_the_end() {
        assert_eq!(Table::parse(&[]).unwrap_err(), Error::Truncated);
        assert_eq!(Table::parse(&[200]).unwrap_err(), Error::Truncated);
        assert_eq!(Table::parse(&[40, 1, 2]).unwrap_err(), Error::Truncated);
    }
}
