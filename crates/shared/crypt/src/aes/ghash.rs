// GHASH: the keyed hash under GCM and GMAC. Field is GF(2^128) modulo
// x^128 + x^7 + x^2 + x + 1, with the bit-reversed byte convention: bit 0 of
// the element is the most significant bit of byte 0, so the reduction shifts
// right and folds 0xe1 into byte 0.
//
// Each absorbed run is zero-padded to a block boundary on its own, which is
// what GCM's separate AAD and ciphertext runs require; there is no carry-over
// buffer between calls.

use super::block::BLOCK_LEN;

const REDUCE: u8 = 0xe1;

/// Multiply `x` by `y` in the GHASH field, in place.
fn mul(x: &mut [u8; BLOCK_LEN], y: &[u8; BLOCK_LEN]) {
    let mut z = [0u8; BLOCK_LEN];
    let mut v = *y;
    for i in 0..(BLOCK_LEN * 8) {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        let m = 0u8.wrapping_sub(bit);
        for j in 0..BLOCK_LEN { z[j] ^= v[j] & m; }
        let lsb = v[BLOCK_LEN - 1] & 1;
        let mut carry = 0u8;
        for j in 0..BLOCK_LEN { let n = v[j] & 1; v[j] = (v[j] >> 1) | (carry << 7); carry = n; }
        v[0] ^= REDUCE & 0u8.wrapping_sub(lsb);
    }
    *x = z;
}

/// GHASH state under a fixed hash subkey.
#[derive(Clone)]
pub struct Ghash { h: [u8; BLOCK_LEN], y: [u8; BLOCK_LEN] }

impl Ghash {
    /// New state under hash subkey `h` (the cipher applied to a zero block).
    /// # C: O(1)
    pub fn new(h: &[u8; BLOCK_LEN]) -> Self { Self { h: *h, y: [0u8; BLOCK_LEN] } }

    /// Absorb exactly one block.
    /// # C: O(1) — 128 field steps
    pub fn update_block(&mut self, b: &[u8; BLOCK_LEN]) {
        for i in 0..BLOCK_LEN { self.y[i] ^= b[i]; }
        mul(&mut self.y, &self.h);
    }

    /// Absorb `data`, zero-padding a trailing partial block.
    /// # C: O(len)
    pub fn update_padded(&mut self, data: &[u8]) {
        let mut off = 0;
        while off < data.len() {
            let n = core::cmp::min(BLOCK_LEN, data.len() - off);
            let mut b = [0u8; BLOCK_LEN];
            b[..n].copy_from_slice(&data[off..off + n]);
            self.update_block(&b);
            off += n;
        }
    }

    /// Absorb the trailing length block: AAD bit count then data bit count,
    /// each a 64-bit big-endian value.
    /// # C: O(1)
    pub fn update_lengths(&mut self, aad_len: u64, data_len: u64) {
        let mut b = [0u8; BLOCK_LEN];
        b[..8].copy_from_slice(&(aad_len * 8).to_be_bytes());
        b[8..].copy_from_slice(&(data_len * 8).to_be_bytes());
        self.update_block(&b);
    }

    /// Current hash value.
    /// # C: O(1)
    pub fn finish(self) -> [u8; BLOCK_LEN] { self.y }
}
