// FSE encoding (RFC 8878 4.1), the mirror of `fse`.
//
// Encoding runs BACKWARD over the symbol list: the decoder reads its bitstream
// in reverse, so the last symbol must be encoded first. The state machine is
// the same table the decoder builds, walked in the opposite direction.
//
// `delta_nb_bits` and `delta_find_state` are the standard FSE formulation: one
// addition and a shift give the bit count, and one addition indexes the next
// state. They are stored per symbol so the inner loop touches two arrays.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::bits::RevWriter;
use crate::{Error, Result};

pub struct EncTable {
    log: u32,
    delta_nb_bits: Vec<u32>,
    delta_find_state: Vec<i32>,
    /// Next-state lookup, grouped by symbol.
    next: Vec<u16>,
}

impl EncTable {
    /// Build from the same normalized counts the decoder uses. The symbol
    /// SPREAD must match `fse::Table::from_normalized` exactly or the two sides
    /// disagree about which state means which symbol.
    /// # C: O(1<<log)
    pub fn from_normalized(norm: &[i16], log: u32) -> Result<Self> {
        if log == 0 || log > 15 { return Err(Error::BadFseTable); }
        let size = 1usize << log;
        let total: i32 = norm.iter().map(|&c| if c < 0 { 1 } else { c as i32 }).sum();
        if total != size as i32 { return Err(Error::BadFseTable); }

        let mut symbols = vec![0u8; size];
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
                loop {
                    pos = (pos + step) & mask;
                    if (pos as i64) <= high { break; }
                }
            }
        }
        if pos != 0 { return Err(Error::BadFseTable); }

        // Cumulative start of each symbol's block of next-states.
        let mut cumul = vec![0u32; norm.len() + 1];
        for (s, &c) in norm.iter().enumerate() {
            cumul[s + 1] = cumul[s] + if c < 0 { 1 } else { c as u32 };
        }
        let mut fill = cumul.clone();
        let mut next = vec![0u16; size];
        for (u, &s) in symbols.iter().enumerate() {
            next[fill[s as usize] as usize] = (size + u) as u16;
            fill[s as usize] += 1;
        }

        let mut delta_nb_bits = vec![0u32; norm.len()];
        let mut delta_find_state = vec![0i32; norm.len()];
        for (s, &c) in norm.iter().enumerate() {
            match c {
                // A count of one and a "less than one" count behave the same:
                // the symbol always costs a full `log` bits.
                -1 | 1 => {
                    delta_nb_bits[s] = (log << 16).wrapping_sub(1 << log);
                    delta_find_state[s] = cumul[s] as i32 - 1;
                }
                0 => {}
                _ => {
                    let max_bits = log - (32 - 1 - ((c as u32) - 1).leading_zeros());
                    let min_state_plus = (c as u32) << max_bits;
                    delta_nb_bits[s] = (max_bits << 16).wrapping_sub(min_state_plus);
                    delta_find_state[s] = cumul[s] as i32 - c as i32;
                }
            }
        }
        Ok(Self { log, delta_nb_bits, delta_find_state, next })
    }
}

/// One encoder state. Held across a whole sequence list.
pub struct State<'t> {
    table: &'t EncTable,
    value: u32,
}

impl<'t> State<'t> {
    /// Seed the state from the symbol that will be decoded FIRST -- which is
    /// the last one encoded. No bits are written here; the state itself is
    /// flushed at the end.
    /// # C: O(1)
    pub fn init(table: &'t EncTable, symbol: u8) -> Self {
        let delta = table.delta_nb_bits[symbol as usize];
        // Rounding by half a unit picks the bit width the decoder will use.
        let nb_bits = (delta.wrapping_add(1 << 15)) >> 16;
        let value = (nb_bits << 16).wrapping_sub(delta);
        let idx = ((value >> nb_bits) as i32 + table.delta_find_state[symbol as usize]) as usize;
        Self { table, value: table.next[idx] as u32 }
    }

    /// Emit one symbol and step the state.
    /// # C: O(1)
    pub fn encode(&mut self, symbol: u8, w: &mut RevWriter) {
        let delta = self.table.delta_nb_bits[symbol as usize];
        let nb_bits = self.value.wrapping_add(delta) >> 16;
        w.push(self.value, nb_bits);
        let idx = ((self.value >> nb_bits) as i32
            + self.table.delta_find_state[symbol as usize]) as usize;
        self.value = self.table.next[idx] as u32;
    }

    /// Write the final state, which is what the decoder reads to start.
    /// # C: O(1)
    pub fn flush(self, w: &mut RevWriter) { w.push(self.value, self.table.log); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::RevReader;
    use crate::fse;
    use crate::tables::{LL_DEFAULT, LL_DEFAULT_LOG, ML_DEFAULT, ML_DEFAULT_LOG, OF_DEFAULT,
        OF_DEFAULT_LOG};

    /// Encode a symbol list and decode it back through the DECODER's table.
    /// This is the only test that matters here: the two tables are built by
    /// separate code and must agree state for state.
    fn round_trip(norm: &[i16], log: u32, syms: &[u8]) {
        let enc = EncTable::from_normalized(norm, log).unwrap();
        let dec = fse::Table::from_normalized(norm, log).unwrap();

        let mut w = RevWriter::new();
        let mut st = State::init(&enc, *syms.last().unwrap());
        // Backward over everything but the last, which the state already holds.
        for &s in syms[..syms.len() - 1].iter().rev() { st.encode(s, &mut w); }
        st.flush(&mut w);
        let buf = w.finish();

        let mut r = RevReader::new(&buf).unwrap();
        let mut d = fse::Decoder::init(&dec, &mut r).unwrap();
        let mut got = Vec::new();
        for i in 0..syms.len() {
            got.push(d.peek());
            if i + 1 < syms.len() { d.advance(&mut r).unwrap(); }
        }
        assert_eq!(got, syms, "encode/decode disagree on the state walk");
        assert!(!r.overran(), "a well-formed stream does not overrun");
    }

    #[test]
    fn the_literal_length_table_round_trips_a_symbol_walk() {
        round_trip(&LL_DEFAULT, LL_DEFAULT_LOG, &[0]);
        round_trip(&LL_DEFAULT, LL_DEFAULT_LOG, &[0, 1, 2, 3, 0, 0, 25, 31]);
        round_trip(&LL_DEFAULT, LL_DEFAULT_LOG, &[35, 34, 33, 32]);
    }

    #[test]
    fn the_match_length_and_offset_tables_round_trip_too() {
        round_trip(&ML_DEFAULT, ML_DEFAULT_LOG, &[0, 1, 2, 3, 52, 51, 0]);
        round_trip(&OF_DEFAULT, OF_DEFAULT_LOG, &[0, 1, 2, 3, 4, 5, 28]);
    }

    #[test]
    fn a_long_run_of_one_symbol_round_trips() {
        // The state must stay inside the table over many steps; a wrong
        // `delta_find_state` drifts and only shows up after a few dozen.
        let syms: Vec<u8> = core::iter::repeat(6u8).take(500).collect();
        round_trip(&LL_DEFAULT, LL_DEFAULT_LOG, &syms);
    }

    #[test]
    fn every_symbol_in_each_predefined_table_round_trips() {
        // A low-probability symbol (count -1) takes a different build path, so
        // sweeping all of them is what proves that path.
        for (dist, log) in [
            (&LL_DEFAULT[..], LL_DEFAULT_LOG),
            (&ML_DEFAULT[..], ML_DEFAULT_LOG),
            (&OF_DEFAULT[..], OF_DEFAULT_LOG),
        ] {
            let syms: Vec<u8> = (0..dist.len() as u8).collect();
            round_trip(dist, log, &syms);
        }
    }
}
