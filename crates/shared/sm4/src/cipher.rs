// SM4 round function, key expansion and block transform. The state is four
// big-endian words: bytes 4*i..4*i+4 of the block are word i, most significant
// byte first, which is the byte order the standard's vectors are printed in.

use crate::params::{CK, FK, L_KEY_ROTATIONS, L_ROTATIONS, SM4_BLOCK_LEN, SM4_RKEY_WORDS, SM4_WORDS};
use crate::sbox::SBOX;

/// Bytes per SM4 block.
pub(crate) const BLOCK: usize = SM4_BLOCK_LEN;

/// Round keys an expanded schedule holds.
pub(crate) const RK_WORDS: usize = SM4_RKEY_WORDS;

/// Non-linear substitution `tau`: the S-box applied to each byte of a word.
fn tau(x: u32) -> u32 {
    let b = x.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

/// Linear transform `L` of the round function.
fn l_round(x: u32) -> u32 {
    x ^ x.rotate_left(L_ROTATIONS[0])
      ^ x.rotate_left(L_ROTATIONS[1])
      ^ x.rotate_left(L_ROTATIONS[2])
      ^ x.rotate_left(L_ROTATIONS[3])
}

/// Linear transform `L'` of the key schedule.
fn l_key(x: u32) -> u32 {
    x ^ x.rotate_left(L_KEY_ROTATIONS[0]) ^ x.rotate_left(L_KEY_ROTATIONS[1])
}

/// Mixer-substitution `T` of the round function: `tau` then `L`.
fn t_round(x: u32) -> u32 { l_round(tau(x)) }

/// Mixer-substitution `T'` of the key schedule: `tau` then `L'`.
fn t_key(x: u32) -> u32 { l_key(tau(x)) }

/// One round: the leading word xored with `T` of the other three and the
/// round key.
fn round(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
    x0 ^ t_round(x1 ^ x2 ^ x3 ^ rk)
}

fn be_words(b: &[u8; BLOCK]) -> [u32; SM4_WORDS] {
    let mut w = [0u32; SM4_WORDS];
    for i in 0..SM4_WORDS {
        w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    w
}

/// Expand a 128-bit key into the 32 encryption round keys.
/// # C: O(1) — 32 schedule rounds
pub(crate) fn expand(key: &[u8; BLOCK]) -> [u32; RK_WORDS] {
    let k = be_words(key);
    let mut rk = [k[0] ^ FK[0], k[1] ^ FK[1], k[2] ^ FK[2], k[3] ^ FK[3]];
    let mut out = [0u32; RK_WORDS];
    let mut i = 0;
    while i < RK_WORDS {
        rk[0] ^= t_key(rk[1] ^ rk[2] ^ rk[3] ^ CK[i]);
        rk[1] ^= t_key(rk[2] ^ rk[3] ^ rk[0] ^ CK[i + 1]);
        rk[2] ^= t_key(rk[3] ^ rk[0] ^ rk[1] ^ CK[i + 2]);
        rk[3] ^= t_key(rk[0] ^ rk[1] ^ rk[2] ^ CK[i + 3]);
        out[i] = rk[0];
        out[i + 1] = rk[1];
        out[i + 2] = rk[2];
        out[i + 3] = rk[3];
        i += SM4_WORDS;
    }
    out
}

/// Transform one block in place under `rk`, applied in index order. Encryption
/// passes the schedule as expanded; decryption passes it reversed.
/// # C: O(1) — 32 rounds
pub(crate) fn crypt_block(rk: &[u32; RK_WORDS], b: &mut [u8; BLOCK]) {
    let mut x = be_words(b);
    let mut i = 0;
    while i < RK_WORDS {
        x[0] = round(x[0], x[1], x[2], x[3], rk[i]);
        x[1] = round(x[1], x[2], x[3], x[0], rk[i + 1]);
        x[2] = round(x[2], x[3], x[0], x[1], rk[i + 2]);
        x[3] = round(x[3], x[0], x[1], x[2], rk[i + 3]);
        i += SM4_WORDS;
    }
    // The output is the final state in reverse word order.
    for i in 0..SM4_WORDS {
        b[4 * i..4 * i + 4].copy_from_slice(&x[SM4_WORDS - 1 - i].to_be_bytes());
    }
}
