// AES round functions and key expansion, over raw byte slices. The state is
// held column-major: byte 4*c+r is row r of column c, so ShiftRows moves
// bytes 4 apart and MixColumns works on contiguous 4-byte runs.

use super::sbox::{INV_SBOX, RCON, SBOX, mul};

/// Bytes per AES block.
pub(super) const BLOCK: usize = 16;

/// Expanded key bytes for the widest schedule this crate builds (AES-256).
pub(super) const MAX_RK: usize = BLOCK * 15;

fn xtime(a: u8) -> u8 { (a << 1) ^ (((a >> 7) & 1) * 0x1b) }

fn add_round_key(b: &mut [u8; BLOCK], rk: &[u8]) { for i in 0..BLOCK { b[i] ^= rk[i]; } }

fn sub_bytes(b: &mut [u8; BLOCK]) { for i in 0..BLOCK { b[i] = SBOX[b[i] as usize]; } }
fn inv_sub_bytes(b: &mut [u8; BLOCK]) { for i in 0..BLOCK { b[i] = INV_SBOX[b[i] as usize]; } }

fn shift_rows(b: &mut [u8; BLOCK]) {
    let s = *b;
    for r in 1..4 { for c in 0..4 { b[4 * c + r] = s[4 * ((c + r) & 3) + r]; } }
}

fn inv_shift_rows(b: &mut [u8; BLOCK]) {
    let s = *b;
    for r in 1..4 { for c in 0..4 { b[4 * ((c + r) & 3) + r] = s[4 * c + r]; } }
}

fn mix_columns(b: &mut [u8; BLOCK]) {
    for c in 0..4 {
        let (a0, a1, a2, a3) = (b[4 * c], b[4 * c + 1], b[4 * c + 2], b[4 * c + 3]);
        let t = a0 ^ a1 ^ a2 ^ a3;
        b[4 * c]     = a0 ^ t ^ xtime(a0 ^ a1);
        b[4 * c + 1] = a1 ^ t ^ xtime(a1 ^ a2);
        b[4 * c + 2] = a2 ^ t ^ xtime(a2 ^ a3);
        b[4 * c + 3] = a3 ^ t ^ xtime(a3 ^ a0);
    }
}

fn inv_mix_columns(b: &mut [u8; BLOCK]) {
    for c in 0..4 {
        let (a0, a1, a2, a3) = (b[4 * c], b[4 * c + 1], b[4 * c + 2], b[4 * c + 3]);
        b[4 * c]     = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
        b[4 * c + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
        b[4 * c + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
        b[4 * c + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
    }
}

/// Expand `key` (16 or 32 bytes) into `rounds+1` round keys at the front of
/// `out`. Caller guarantees `out.len() >= BLOCK * (rounds + 1)`.
pub(super) fn expand(key: &[u8], out: &mut [u8], rounds: usize) {
    let nk = key.len() / 4;
    out[..key.len()].copy_from_slice(key);
    let words = 4 * (rounds + 1);
    for i in nk..words {
        let mut t = [out[4 * i - 4], out[4 * i - 3], out[4 * i - 2], out[4 * i - 1]];
        if i % nk == 0 {
            t = [SBOX[t[1] as usize], SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
            t[0] ^= RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            for j in 0..4 { t[j] = SBOX[t[j] as usize]; }
        }
        for j in 0..4 { out[4 * i + j] = out[4 * (i - nk) + j] ^ t[j]; }
    }
}

/// Encrypt one block in place with an expanded schedule.
pub(super) fn encrypt(rk: &[u8], rounds: usize, b: &mut [u8; BLOCK]) {
    add_round_key(b, &rk[..BLOCK]);
    for r in 1..rounds {
        sub_bytes(b); shift_rows(b); mix_columns(b);
        add_round_key(b, &rk[r * BLOCK..(r + 1) * BLOCK]);
    }
    sub_bytes(b); shift_rows(b);
    add_round_key(b, &rk[rounds * BLOCK..(rounds + 1) * BLOCK]);
}

/// Decrypt one block in place with an expanded schedule.
pub(super) fn decrypt(rk: &[u8], rounds: usize, b: &mut [u8; BLOCK]) {
    add_round_key(b, &rk[rounds * BLOCK..(rounds + 1) * BLOCK]);
    for r in (1..rounds).rev() {
        inv_shift_rows(b); inv_sub_bytes(b);
        add_round_key(b, &rk[r * BLOCK..(r + 1) * BLOCK]);
        inv_mix_columns(b);
    }
    inv_shift_rows(b); inv_sub_bytes(b);
    add_round_key(b, &rk[..BLOCK]);
}
