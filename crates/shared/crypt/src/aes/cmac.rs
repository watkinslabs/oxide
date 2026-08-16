// AES-CMAC (the CBC-MAC variant with subkey-masked final block) and AES-GMAC,
// the two integrity checks 802.11 management-frame protection uses.
//
// CMAC derives two subkeys from the cipher applied to a zero block by
// doubling in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1: K1 = 2L,
// K2 = 4L. A message whose length is a non-zero multiple of the block size
// masks its final block with K1; any other length is padded with a 0x80 byte
// then zeros and masked with K2. Truncating the output is the defined way to
// obtain a shorter tag, so an 8-byte tag is the first 8 bytes of the 16.

use super::block::{AesKey, BLOCK_LEN};
use super::gcm;

/// Doubling constant for GF(2^128) in the CMAC bit order.
const DBL_POLY: u8 = 0x87;

/// Full CMAC output length, bytes.
pub const CMAC_LEN: usize = BLOCK_LEN;
/// Truncated CMAC length used for management-frame protection, bytes.
pub const CMAC_LEN_8: usize = 8;
/// GMAC output length, bytes.
pub const GMAC_LEN: usize = 16;

/// Left-shift a block by one bit, folding the reduction polynomial on carry.
fn dbl(b: &mut [u8; BLOCK_LEN]) {
    let msb = b[0] >> 7;
    let mut carry = 0u8;
    for i in (0..BLOCK_LEN).rev() { let n = b[i] >> 7; b[i] = (b[i] << 1) | carry; carry = n; }
    b[BLOCK_LEN - 1] ^= DBL_POLY & 0u8.wrapping_sub(msb);
}

fn subkeys(key: &AesKey) -> ([u8; BLOCK_LEN], [u8; BLOCK_LEN]) {
    let mut k1 = [0u8; BLOCK_LEN];
    key.encrypt_block(&mut k1);
    dbl(&mut k1);
    let mut k2 = k1;
    dbl(&mut k2);
    (k1, k2)
}

/// Full 16-byte CMAC of `msg`.
/// # C: O(len(msg))
pub fn cmac_full(key: &AesKey, msg: &[u8]) -> [u8; CMAC_LEN] {
    let (k1, k2) = subkeys(key);
    let mut x = [0u8; BLOCK_LEN];

    let whole = if msg.is_empty() { 0 } else { (msg.len() - 1) / BLOCK_LEN };
    for c in 0..whole {
        let b = &msg[c * BLOCK_LEN..(c + 1) * BLOCK_LEN];
        for i in 0..BLOCK_LEN { x[i] ^= b[i]; }
        key.encrypt_block(&mut x);
    }

    let tail = &msg[whole * BLOCK_LEN..];
    let mut last = [0u8; BLOCK_LEN];
    last[..tail.len()].copy_from_slice(tail);
    if tail.len() == BLOCK_LEN {
        for i in 0..BLOCK_LEN { last[i] ^= k1[i]; }
    } else {
        last[tail.len()] = 0x80;
        for i in 0..BLOCK_LEN { last[i] ^= k2[i]; }
    }
    for i in 0..BLOCK_LEN { x[i] ^= last[i]; }
    key.encrypt_block(&mut x);
    x
}

/// CMAC of `msg` into `out`, truncated to `out.len()` (8 or 16). Lengths
/// above 16 are filled only for the first 16 bytes.
/// # C: O(len(msg))
pub fn cmac(key: &AesKey, msg: &[u8], out: &mut [u8]) {
    let t = cmac_full(key, msg);
    let n = core::cmp::min(out.len(), CMAC_LEN);
    out[..n].copy_from_slice(&t[..n]);
}

/// AES-GMAC: the GCM tag over `aad` with an empty payload, under the
/// pre-counter block built from the 12-byte `iv`.
/// # C: O(len(aad))
pub fn gmac(key: &AesKey, iv: &[u8; gcm::IV_LEN], aad: &[u8], out: &mut [u8; GMAC_LEN]) {
    *out = gcm::tag_empty_payload(key, iv, aad);
}
