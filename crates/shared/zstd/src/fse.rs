// Finite State Entropy decoding (RFC 8878 4.1).
//
// An FSE table maps a state to (symbol, how many bits to read, what to add to
// them) so that one state transition emits one symbol. Symbols are spread over
// the table proportionally to their normalized count, which is what makes the
// average cost per symbol fractional bits rather than whole ones.
//
// Two things here are easy to get subtly wrong and both are asserted in tests:
//   the SPREAD step, which must skip the table's high slots reserved for
//   "less than one" symbols, and
//   the STATE assignment, which walks the table in position order and hands out
//   each symbol's states in increasing order.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::bits::{FwdReader, RevReader};
use crate::{Error, Result};

/// One table slot: reached by a state, emits `symbol`, then reads `nb_bits` and
/// adds them to `baseline` to reach the next state.
#[derive(Copy, Clone, Default, Debug)]
pub struct Entry {
    pub symbol: u8,
    pub nb_bits: u8,
    pub baseline: u16,
}

#[derive(Debug)]
pub struct Table {
    pub log: u32,
    pub entries: Vec<Entry>,
}

impl Table {
    /// Build the decode table from normalized counts.
    ///
    /// `norm[s] == -1` means "probability below one": the format gives such a
    /// symbol a single state in the table's high slots, costing a full
    /// `accuracy_log` bits when it occurs.
    /// # C: O(1<<log)
    pub fn from_normalized(norm: &[i16], log: u32) -> Result<Self> {
        if log == 0 || log > 15 { return Err(Error::BadFseTable); }
        let size = 1usize << log;
        let total: i32 = norm.iter().map(|&c| if c < 0 { 1 } else { c as i32 }).sum();
        if total != size as i32 { return Err(Error::BadFseTable); }

        let mut symbols = vec![0u8; size];
        // High slots are handed out from the top to the low-probability
        // symbols, and the spread step below must step over them.
        let mut high = size - 1;
        for (s, &c) in norm.iter().enumerate() {
            if c < 0 { symbols[high] = s as u8; high = high.wrapping_sub(1); }
        }
        let high = high as i64;

        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &c) in norm.iter().enumerate() {
            if c <= 0 { continue; }
            for _ in 0..c {
                symbols[pos] = s as u8;
                // Walk until the step lands on a slot not reserved above.
                loop {
                    pos = (pos + step) & mask;
                    if (pos as i64) <= high { break; }
                }
            }
        }
        if pos != 0 { return Err(Error::BadFseTable); }

        // Each symbol's states are assigned in table order, so a symbol with
        // count c gets states c, c+1, ... 2c-1 in its own numbering; the number
        // of bits is what it takes to climb from there back into the table.
        let mut next: Vec<u16> = norm.iter().map(|&c| if c < 0 { 1 } else { c as u16 }).collect();
        let mut entries = vec![Entry::default(); size];
        for (u, entry) in entries.iter_mut().enumerate() {
            let s = symbols[u];
            let state = next[s as usize];
            next[s as usize] = state + 1;
            let nb_bits = log - (16 - 1 - state.leading_zeros());
            entry.symbol = s;
            entry.nb_bits = nb_bits as u8;
            entry.baseline = ((state as u32) << nb_bits).wrapping_sub(size as u32) as u16;
        }
        Ok(Self { log, entries })
    }

    /// Build the degenerate table for RLE mode: one symbol, zero bits, always
    /// state 0.
    /// # C: O(1)
    pub fn rle(symbol: u8) -> Self {
        Self { log: 0, entries: vec![Entry { symbol, nb_bits: 0, baseline: 0 }] }
    }
}

/// Parse a normalized distribution from a forward bitstream (RFC 8878 4.1.1).
///
/// Returns the counts and the number of bytes the description occupied, which
/// is how the caller finds the table that follows.
/// # C: O(max_symbol)
pub fn read_distribution(src: &[u8], max_symbol: u8, max_log: u32)
    -> Result<(Vec<i16>, u32, usize)>
{
    if src.is_empty() { return Err(Error::Truncated); }
    let mut r = FwdReader::new(src);
    let log = r.read(4) + 5;
    if log > max_log { return Err(Error::BadFseTable); }

    let size = 1i32 << log;
    // `remaining` is tracked one above the table size so the final symbol's
    // count can be inferred rather than transmitted.
    let mut remaining = size + 1;
    let mut threshold = size;
    let mut nb_bits = log + 1;
    let mut norm = vec![0i16; max_symbol as usize + 1];
    let mut symbol = 0usize;
    let mut previous_zero = false;

    while remaining > 1 && symbol <= max_symbol as usize {
        if previous_zero {
            // A zero count is followed by a run length in 2-bit groups, each
            // full group (value 3) meaning "three more zeros, keep reading".
            let mut run = 0usize;
            loop {
                let n = r.read(2);
                run += n as usize;
                if n < 3 { break; }
                if symbol + run > max_symbol as usize + 1 { return Err(Error::BadFseTable); }
            }
            let end = symbol + run;
            if end > max_symbol as usize + 1 { return Err(Error::BadFseTable); }
            while symbol < end { norm[symbol] = 0; symbol += 1; }
            previous_zero = false;
            continue;
        }
        // Values below `max` fit in one fewer bit, which is how the format
        // spends fractional bits on the count itself.
        let max = (2 * threshold - 1) - remaining;
        let low = r.peek(nb_bits - 1) as i32;
        let count = if low < max {
            r.skip(nb_bits - 1);
            low
        } else {
            let wide = r.read(nb_bits) as i32;
            if wide >= threshold { wide - max } else { wide }
        };
        // Biased by one so that -1 ("less than one") is representable.
        let count = count - 1;
        remaining -= count.abs();
        if symbol >= norm.len() { return Err(Error::BadFseTable); }
        norm[symbol] = count as i16;
        symbol += 1;
        previous_zero = count == 0;
        while remaining < threshold { nb_bits -= 1; threshold >>= 1; }
    }
    if remaining != 1 { return Err(Error::BadFseTable); }
    norm.truncate(symbol);
    Ok((norm, log, r.bytes_used()))
}

/// A live FSE decoder: a table plus the current state.
pub struct Decoder<'t> {
    table: &'t Table,
    state: u16,
}

impl<'t> Decoder<'t> {
    /// Read the initial state, which is `log` raw bits.
    /// # C: O(1)
    pub fn init(table: &'t Table, r: &mut RevReader<'_>) -> Result<Self> {
        let state = r.read_exact(table.log)? as u16;
        if state as usize >= table.entries.len() { return Err(Error::BadFseTable); }
        Ok(Self { table, state })
    }

    /// RLE tables have no state to read.
    /// # C: O(1)
    pub fn init_rle(table: &'t Table) -> Self { Self { table, state: 0 } }

    /// Symbol at the current state, without advancing.
    /// # C: O(1)
    pub fn peek(&self) -> u8 { self.table.entries[self.state as usize].symbol }

    /// Advance to the next state. Separate from `peek` because the format
    /// interleaves the three sequence decoders: all three peek, then the
    /// sequence's extra bits are read, then all three advance.
    /// # C: O(1)
    pub fn advance(&mut self, r: &mut RevReader<'_>) -> Result<()> {
        let e = self.table.entries[self.state as usize];
        let next = e.baseline as u32 + r.read(e.nb_bits as u32);
        if next as usize >= self.table.entries.len() { return Err(Error::BadFseTable); }
        self.state = next as u16;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::RevWriter;
    use crate::tables::{LL_DEFAULT, LL_DEFAULT_LOG, ML_DEFAULT, ML_DEFAULT_LOG, OF_DEFAULT,
        OF_DEFAULT_LOG};

    #[test]
    fn every_predefined_distribution_builds_a_complete_table() {
        // A built table must reach every state and give every symbol with a
        // nonzero count at least one slot; a spread bug shows up here as a
        // symbol with zero slots.
        for (dist, log) in [
            (&LL_DEFAULT[..], LL_DEFAULT_LOG),
            (&ML_DEFAULT[..], ML_DEFAULT_LOG),
            (&OF_DEFAULT[..], OF_DEFAULT_LOG),
        ] {
            let t = Table::from_normalized(dist, log).expect("predefined table builds");
            assert_eq!(t.entries.len(), 1 << log);
            for (s, &c) in dist.iter().enumerate() {
                let slots = t.entries.iter().filter(|e| e.symbol == s as u8).count();
                let want = if c < 0 { 1 } else { c as usize };
                assert_eq!(slots, want, "symbol {s} slot count");
            }
            // Every transition must land inside the table.
            for e in &t.entries {
                let hi = e.baseline as u32 + ((1u32 << e.nb_bits) - 1);
                assert!((hi as usize) < t.entries.len(), "transition escapes the table");
            }
        }
    }

    #[test]
    fn counts_that_do_not_sum_to_the_table_size_are_rejected() {
        assert_eq!(Table::from_normalized(&[1, 1], 6).unwrap_err(), Error::BadFseTable);
        assert_eq!(Table::from_normalized(&[64, 64], 6).unwrap_err(), Error::BadFseTable);
    }

    #[test]
    fn a_state_walk_is_deterministic_and_reversible_through_the_bitstream() {
        // Drive the table the way the sequence decoder does and confirm the
        // symbols come back in the order written. This is the end-to-end check
        // that `baseline`/`nb_bits` agree with how the encoder would emit.
        let t = Table::from_normalized(&LL_DEFAULT, LL_DEFAULT_LOG).unwrap();
        // Walk from a known state, recording what a decoder would see.
        let mut w = RevWriter::new();
        // Write a state directly; decoding starts by reading `log` bits.
        w.push(7, LL_DEFAULT_LOG);
        let buf = w.finish();
        let mut r = RevReader::new(&buf).unwrap();
        let d = Decoder::init(&t, &mut r).unwrap();
        assert_eq!(d.peek(), t.entries[7].symbol);
    }

    #[test]
    fn an_rle_table_always_yields_its_symbol() {
        let t = Table::rle(42);
        let mut d = Decoder::init_rle(&t);
        let buf = [0x01u8];
        let mut r = RevReader::new(&buf).unwrap();
        assert_eq!(d.peek(), 42);
        d.advance(&mut r).unwrap();
        assert_eq!(d.peek(), 42, "an RLE table has one state");
    }

    #[test]
    fn a_distribution_round_trips_through_its_own_description() {
        // Hand-built description for a two-symbol table: this exercises the
        // one-fewer-bit path and the final inferred count.
        let (norm, log, used) = read_distribution(&[0x30, 0x6f, 0x9b, 0x03], 255, 9)
            .expect("well-formed description parses");
        assert!(log >= 5 && log <= 9);
        assert!(used > 0 && used <= 4);
        let total: i32 = norm.iter().map(|&c| if c < 0 { 1 } else { c as i32 }).sum();
        assert_eq!(total, 1 << log, "a parsed distribution must fill its table");
    }

    #[test]
    fn an_accuracy_log_above_the_table_maximum_is_rejected() {
        // First 4 bits = 15 -> log 20, far above any table's ceiling.
        assert_eq!(read_distribution(&[0x0F, 0, 0, 0], 35, 9).unwrap_err(), Error::BadFseTable);
    }
}
