// Fixed-arity fast paths — Linux `siphash_Nu64` and the
// `siphash_2u32`/`siphash_4u32` static inlines.
// Each is exactly `siphash` over the little-endian serialisation of its
// arguments; they exist so a caller with a small fixed record never builds a
// scratch buffer. The `u32` forms pack argument pairs low-word-first, which is
// what makes `siphash_2u32(a, b, k) == siphash_1u64((b << 32) | a, k)`.

use crate::permute::{Key, State};

/// Bytes contributed per `u64` argument, for the length staged in `b`.
const U64_LEN: usize = 8;
/// Bytes contributed per `u32` argument.
const U32_LEN: usize = 4;
/// Shift placing the second member of a packed `u32` pair in the high half.
const PAIR_SHIFT: u32 = 32;

/// Pack two `u32` into one message word, first in the low half. # C: O(1)
#[inline]
const fn pair(first: u32, second: u32) -> u64 { (second as u64) << PAIR_SHIFT | first as u64 }

/// # C: O(1)
pub fn siphash_1u64(first: u64, key: &Key) -> u64 {
    let mut st = State::new(U64_LEN, key);
    st.absorb(first);
    st.finish()
}

/// # C: O(1)
pub fn siphash_2u64(first: u64, second: u64, key: &Key) -> u64 {
    let mut st = State::new(2 * U64_LEN, key);
    st.absorb(first); st.absorb(second);
    st.finish()
}

/// # C: O(1)
pub fn siphash_3u64(first: u64, second: u64, third: u64, key: &Key) -> u64 {
    let mut st = State::new(3 * U64_LEN, key);
    st.absorb(first); st.absorb(second); st.absorb(third);
    st.finish()
}

/// # C: O(1)
pub fn siphash_4u64(first: u64, second: u64, third: u64, forth: u64, key: &Key) -> u64 {
    let mut st = State::new(4 * U64_LEN, key);
    st.absorb(first); st.absorb(second); st.absorb(third); st.absorb(forth);
    st.finish()
}

/// # C: O(1)
pub fn siphash_1u32(first: u32, key: &Key) -> u64 {
    let mut st = State::new(U32_LEN, key);
    st.tail(first as u64);
    st.finish()
}

/// # C: O(1)
pub fn siphash_2u32(first: u32, second: u32, key: &Key) -> u64 {
    siphash_1u64(pair(first, second), key)
}

/// # C: O(1)
pub fn siphash_3u32(first: u32, second: u32, third: u32, key: &Key) -> u64 {
    let mut st = State::new(3 * U32_LEN, key);
    st.absorb(pair(first, second));
    st.tail(third as u64);
    st.finish()
}

/// # C: O(1)
pub fn siphash_4u32(first: u32, second: u32, third: u32, forth: u32, key: &Key) -> u64 {
    siphash_2u64(pair(first, second), pair(third, forth), key)
}
