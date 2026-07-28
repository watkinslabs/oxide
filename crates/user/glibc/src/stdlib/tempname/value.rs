// random_value arithmetic for temp names — glibc sysdeps/posix/tempname.c
// (gnulib sync lib/tempname.c): the `letters[]` alphabet, the base-62 digit
// pool that peels BASE_62_DIGITS letters out of one 64-bit draw, the
// `biased_min` rejection rule, and `mix_random_values` for the ersatz path.
//
// Every function here is a pure function of its arguments — no clock, no
// syscall, no hidden state. That is the property that makes a temp name an
// image of the getrandom(2) bytes and nothing else; the old clock-seeded LCG
// failed exactly here (a predictable name = /tmp symlink race).
//
// Ungated on purpose (no `#![cfg(feature = "freestanding")]`) so hosted
// `cargo test` compiles and runs the tests in `super::tests`.

// glibc `static const char letters[]`.
pub const LETTERS: &[u8; BASE] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const BASE: usize = 62;
const BASE_U64: u64 = BASE as u64;

// glibc BASE_62_DIGITS: 62**10 < UINT_FAST64_MAX < 62**11, so one 64-bit
// random_value yields 10 base-62 digits.
pub const BASE_62_DIGITS: u32 = 10;
// glibc BASE_62_POWER = 62**10.
pub const BASE_62_POWER: u64 = 839_299_365_868_340_224;
// glibc `biased_min = RANDOM_VALUE_MAX - RANDOM_VALUE_MAX % BASE_62_POWER`.
// A draw at or above this cannot produce BASE_62_DIGITS unbiased digits.
pub const BIASED_MIN: u64 = u64::MAX - u64::MAX % BASE_62_POWER;
// sizeof(random_value) — the draw width glibc asks getrandom(2) for.
pub const RANDOM_VALUE_BYTES: usize = core::mem::size_of::<u64>();
// glibc `__gen_tempname` passes x_suffix_len = 6 ("XXXXXX").
pub const X_SUFFIX_LEN: usize = 6;
// glibc ATTEMPTS_MIN = 62**3 = 238328, which equals TMP_MAX, so the retry
// budget is 238328 either way.
pub const ATTEMPTS: u32 = 238_328;

// glibc mix_random_values() — an LCG step xored with the second input. Only
// reached when getrandom(2) is unavailable.
const MIX_MUL: u64 = 2_862_933_555_777_941_757;
const MIX_ADD: u64 = 3_037_000_493;

/// # C: mix_random_values(r, s)
#[inline]
pub fn mix_random_values(r: u64, s: u64) -> u64 { MIX_MUL.wrapping_mul(r).wrapping_add(MIX_ADD) ^ s }

/// # C: `random_bits(&v, v) && biased_min <= v` — redraw predicate.
/// Bias only matters when the bits are high quality; the ersatz fallback is
/// biased regardless, so glibc accepts it as-is rather than looping forever.
#[inline]
pub fn needs_redraw(high_quality: bool, v: u64) -> bool { high_quality && v >= BIASED_MIN }

/// # C: bytes of getrandom(2) output needed to emit `n` letters
pub const fn bytes_needed(n: usize) -> usize {
    let d = BASE_62_DIGITS as usize;
    ((n + d - 1) / d) * RANDOM_VALUE_BYTES
}

// glibc's `vdigbuf` / `vdigits` pair: one draw, BASE_62_DIGITS letters peeled
// off the low end.
pub struct DigitPool { v: u64, left: u32 }

impl DigitPool {
    /// # C: vdigits = 0 (pool starts empty, first letter forces a draw)
    pub const fn new() -> Self { Self { v: 0, left: 0 } }
    /// # C: vdigits == 0
    #[inline]
    pub fn is_empty(&self) -> bool { self.left == 0 }
    /// # C: vdigbuf = v; vdigits = BASE_62_DIGITS
    #[inline]
    pub fn refill(&mut self, v: u64) { self.v = v; self.left = BASE_62_DIGITS; }
    /// # C: letters[vdigbuf % 62]; vdigbuf /= 62; vdigits--
    /// Returns the alphabet's first letter when the pool is empty; callers
    /// check `is_empty` first, and an empty pool holds v == 0 anyway.
    #[inline]
    pub fn next_letter(&mut self) -> u8 {
        let c = LETTERS[(self.v % BASE_U64) as usize];
        self.v /= BASE_U64;
        self.left = self.left.saturating_sub(1);
        c
    }
}

impl Default for DigitPool { fn default() -> Self { Self::new() } }

/// # C: fill out[] with letters derived only from `bytes`
/// `bytes` is consecutive little-endian random_value draws (both target arches
/// are little-endian, so this is the byte→value mapping getrandom(2) produces
/// when glibc reads straight into a `uint_fast64_t`). False when `bytes` is
/// shorter than `bytes_needed(out.len())` — a short getrandom(2) read.
pub fn fill_suffix(bytes: &[u8], out: &mut [u8]) -> bool {
    if bytes.len() < bytes_needed(out.len()) { return false; }
    let mut pool = DigitPool::new();
    let mut off = 0usize;
    for c in out.iter_mut() {
        if pool.is_empty() {
            let mut w = [0u8; RANDOM_VALUE_BYTES];
            w.copy_from_slice(&bytes[off..off + RANDOM_VALUE_BYTES]);
            pool.refill(u64::from_le_bytes(w));
            off += RANDOM_VALUE_BYTES;
        }
        *c = pool.next_letter();
    }
    true
}
