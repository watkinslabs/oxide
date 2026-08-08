// `siphash(data, key)` over an arbitrary byte buffer — Linux's
// `__siphash_unaligned`. Rust slices carry their length, so
// the aligned/unaligned split and the `load_unaligned_zeropad` fast path have
// no analogue here; the byte-at-a-time trailer below is the portable
// `switch (left)` arm, which produces identical output.

use crate::permute::{Key, State};

/// Message-word size; the trailer is whatever does not fill one. # bytes
const WORD: usize = 8;

/// SipHash-2-4 of `data` under `key`. # C: O(data.len())
pub fn siphash(data: &[u8], key: &Key) -> u64 {
    let mut st = State::new(data.len(), key);
    let whole = data.len() - data.len() % WORD;
    let (body, left) = data.split_at(whole);
    for w in body.chunks_exact(WORD) {
        st.absorb(u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]));
    }
    // Linux ORs the remaining 1..=7 bytes into `b` little-endian, leaving the
    // high byte (the length) that PREAMBLE already placed there untouched.
    let mut tail = 0u64;
    for (i, byte) in left.iter().enumerate() { tail |= (*byte as u64) << (8 * i); }
    st.tail(tail);
    st.finish()
}
