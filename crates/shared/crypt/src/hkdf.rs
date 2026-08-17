// HKDF-SHA512 (RFC 5869): extract a pseudorandom key, then expand it into as
// much keying material as a caller asks for.
//
// Extract is HMAC(salt, ikm) — salt is the KEY and the input keying material
// is the MESSAGE, which is the opposite of what the argument order suggests
// and the single most common way to get a self-consistent wrong answer. An
// absent salt is a block of zeroes the width of the hash, not an empty key.
//
// Expand chains: T(0) is empty, T(i) = HMAC(prk, T(i-1) || info || i), and the
// counter is a single byte starting at ONE. Starting at zero shifts every
// output block and still round-trips against itself.

use crate::hmac::{HmacSha512, HMAC_SHA512_LEN};

/// Output width of one expand iteration.
pub const HKDF_SHA512_LEN: usize = HMAC_SHA512_LEN;
/// Longest output the one-byte counter can address.
pub const HKDF_SHA512_MAX_OUT: usize = 255 * HKDF_SHA512_LEN;

/// An extracted pseudorandom key, ready to expand many times.
#[derive(Clone)]
pub struct HkdfSha512 { prk: HmacSha512 }

impl HkdfSha512 {
    /// HKDF-Extract. A caller with no salt passes an empty slice, which is
    /// the all-zero block the specification defines.
    /// # C: O(len(salt) + len(ikm))
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        let zeros = [0u8; HKDF_SHA512_LEN];
        let s = if salt.is_empty() { &zeros[..] } else { salt };
        let prk = HmacSha512::new(s).mac(ikm);
        Self { prk: HmacSha512::new(&prk) }
    }

    /// HKDF-Expand into `okm`, with the info string given in pieces so a
    /// caller can prefix a context byte without joining buffers.
    ///
    /// Returns `false` for an output longer than the one-byte counter can
    /// address; the buffer is left untouched in that case.
    /// # C: O(len(okm))
    pub fn expand(&self, info: &[&[u8]], okm: &mut [u8]) -> bool {
        if okm.len() > HKDF_SHA512_MAX_OUT { return false; }
        let mut prev = [0u8; HKDF_SHA512_LEN];
        let mut counter: u8 = 1;
        let mut done = 0usize;
        while done < okm.len() {
            let mut c = self.prk.start();
            if done != 0 { c.update(&prev); }
            for part in info { c.update(part); }
            c.update(&[counter]);
            prev = c.finish();
            let take = HKDF_SHA512_LEN.min(okm.len() - done);
            okm[done..done + take].copy_from_slice(&prev[..take]);
            done += take;
            counter = counter.wrapping_add(1);
        }
        true
    }
}

#[cfg(test)]
#[path = "tests/hkdf.rs"]
mod tests;
