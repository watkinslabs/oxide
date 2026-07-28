// ChaCha20 block function (RFC 8439 §2.3), the permutation Linux's
// `drivers/char/random.c` builds its CRNG on.
//
// Block only — no AEAD, no Poly1305. Two consumers: the fast-key-erasure
// output path and the entropy-absorb rekey, both in `pool.rs`.

/// `"expand 32-byte k"` — RFC 8439 §2.3 constants.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
/// One ChaCha20 output block.
pub const BLOCK_BYTES: usize = 64;
/// Key words. The 256-bit key is the CRNG state Linux erases per output.
pub const KEY_WORDS: usize = 8;
/// Linux uses 20 rounds (10 double rounds) for its CRNG.
const DOUBLE_ROUNDS: usize = 10;

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

/// One ChaCha20 block under `key`, block counter `counter`, nonce `nonce`.
/// # C: O(1) — 20 fixed rounds
pub fn block(key: &[u32; KEY_WORDS], counter: u32, nonce: [u32; 3]) -> [u8; BLOCK_BYTES] {
    let mut s: [u32; 16] = [
        SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3],
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];
    let init = s;
    for _ in 0..DOUBLE_ROUNDS {
        quarter_round(&mut s, 0, 4,  8, 12);
        quarter_round(&mut s, 1, 5,  9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7,  8, 13);
        quarter_round(&mut s, 3, 4,  9, 14);
    }
    let mut out = [0u8; BLOCK_BYTES];
    for i in 0..16 {
        let w = s[i].wrapping_add(init[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Read the first 32 bytes of a block as the next key. # C: O(1)
pub fn key_from(block: &[u8; BLOCK_BYTES]) -> [u32; KEY_WORDS] {
    let mut k = [0u32; KEY_WORDS];
    for i in 0..KEY_WORDS {
        k[i] = u32::from_le_bytes([block[i * 4], block[i * 4 + 1],
                                   block[i * 4 + 2], block[i * 4 + 3]]);
    }
    k
}

#[cfg(test)]
#[path = "chacha/tests.rs"]
mod tests;
