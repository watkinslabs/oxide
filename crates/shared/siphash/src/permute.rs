// The SipHash-2-4 core: IV constants, the ARX permutation, and the
// preamble/postamble that bracket every variant. Mirrors Linux's
// `SIPHASH_PERMUTATION` / `PREAMBLE` / `POSTAMBLE` macros.

/// Linux `SIPHASH_CONST_0`..`_3` — the ASCII of "somepseudorandomlygeneratedbytes".
const IV0: u64 = 0x736f_6d65_7073_6575;
const IV1: u64 = 0x646f_7261_6e64_6f6d;
const IV2: u64 = 0x6c79_6765_6e65_7261;
const IV3: u64 = 0x7465_6462_7974_6573;

/// Rounds after each absorbed word (the "2" of SipHash-2-4).
const COMPRESSION_ROUNDS: usize = 2;
/// Rounds in the finalisation (the "4" of SipHash-2-4).
const FINALIZATION_ROUNDS: usize = 4;
/// Postamble XOR that separates finalisation from compression.
const FINALIZATION_XOR: u64 = 0xff;
/// Bit position of the length byte in the trailing word `b`.
const LENGTH_SHIFT: u32 = 56;

/// A 128-bit SipHash key. Linux `siphash_key_t` — `key[0]`, `key[1]`.
///
/// Must come from a CSPRNG. The whole construction is only as unpredictable
/// as this value; a key derived from a clock or a constant makes every output
/// reproducible by anyone who can guess it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Key { pub k0: u64, pub k1: u64 }

impl Key {
    /// Build a key from 16 CSPRNG bytes, little-endian per Linux. # C: O(1)
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        Self {
            k0: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            k1: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        }
    }
}

/// The four-word SipHash state, threaded through absorb + finalise.
pub(crate) struct State { v0: u64, v1: u64, v2: u64, v3: u64, b: u64 }

impl State {
    /// Linux `PREAMBLE(len)`: seed the IV with the key and stage the length
    /// byte in the trailing word. # C: O(1)
    #[inline]
    pub(crate) fn new(len: usize, key: &Key) -> Self {
        Self {
            v0: IV0 ^ key.k0, v1: IV1 ^ key.k1,
            v2: IV2 ^ key.k0, v3: IV3 ^ key.k1,
            b: (len as u64) << LENGTH_SHIFT,
        }
    }

    /// One `SIPHASH_PERMUTATION` round. # C: O(1)
    #[inline]
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1); self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0; self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3); self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3); self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1); self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2; self.v2 = self.v2.rotate_left(32);
    }

    /// Absorb one whole little-endian 64-bit message word. # C: O(1)
    #[inline]
    pub(crate) fn absorb(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..COMPRESSION_ROUNDS { self.round(); }
        self.v0 ^= m;
    }

    /// OR the trailing partial word into `b` (Linux `b |= ...`). # C: O(1)
    #[inline]
    pub(crate) fn tail(&mut self, bits: u64) { self.b |= bits; }

    /// Linux `POSTAMBLE`: absorb `b`, then four finalisation rounds. # C: O(1)
    #[inline]
    pub(crate) fn finish(mut self) -> u64 {
        self.v3 ^= self.b;
        for _ in 0..COMPRESSION_ROUNDS { self.round(); }
        self.v0 ^= self.b;
        self.v2 ^= FINALIZATION_XOR;
        for _ in 0..FINALIZATION_ROUNDS { self.round(); }
        (self.v0 ^ self.v1) ^ (self.v2 ^ self.v3)
    }
}
