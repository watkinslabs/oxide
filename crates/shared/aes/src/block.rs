//! AES-128 key schedule and single-block encryption.
//!
//! Encrypt direction only. CMAC — the only consumer here — never decrypts, and
//! an unused inverse cipher is machinery with no caller.

use crate::params::{
    AES128_KEY_LEN, AES128_KEY_WORDS, AES128_ROUNDS, AES128_SCHEDULE_WORDS,
    AES_BLOCK_LEN, RCON,
};
use crate::sbox::{sub_byte, xtime};

/// An expanded AES-128 encryption key.
///
/// Clone is deliberately absent: a round schedule is key material and copying
/// it should be an explicit act at the call site, not an implicit one.
pub struct Aes128 {
    /// Round keys as words, four consecutive words per round key.
    rk: [[u8; 4]; AES128_SCHEDULE_WORDS],
}

/// Rotate a schedule word left by one byte. # C: O(1)
fn rot_word(w: [u8; 4]) -> [u8; 4] { [w[1], w[2], w[3], w[0]] }

/// Substitute every byte of a schedule word. # C: O(1)
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [sub_byte(w[0]), sub_byte(w[1]), sub_byte(w[2]), sub_byte(w[3])]
}

impl Aes128 {
    /// Expand a 128-bit key into its round schedule. # C: O(1)
    pub fn new(key: &[u8; AES128_KEY_LEN]) -> Aes128 {
        let mut rk = [[0u8; 4]; AES128_SCHEDULE_WORDS];
        let mut i = 0;
        while i < AES128_KEY_WORDS {
            rk[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
            i += 1;
        }
        while i < AES128_SCHEDULE_WORDS {
            let mut t = rk[i - 1];
            if i % AES128_KEY_WORDS == 0 {
                t = sub_word(rot_word(t));
                t[0] ^= RCON[i / AES128_KEY_WORDS - 1];
            }
            let p = rk[i - AES128_KEY_WORDS];
            rk[i] = [p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]];
            i += 1;
        }
        Aes128 { rk }
    }

    /// Encrypt one block in place. # C: O(1)
    pub fn encrypt_block(&self, b: &mut [u8; AES_BLOCK_LEN]) {
        self.add_round_key(b, 0);
        let mut round = 1;
        while round < AES128_ROUNDS {
            sub_bytes(b);
            shift_rows(b);
            mix_columns(b);
            self.add_round_key(b, round);
            round += 1;
        }
        sub_bytes(b);
        shift_rows(b);
        self.add_round_key(b, AES128_ROUNDS);
    }

    /// Encrypt one block, returning the result rather than mutating. # C: O(1)
    pub fn encrypt(&self, input: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
        let mut b = *input;
        self.encrypt_block(&mut b);
        b
    }

    fn add_round_key(&self, b: &mut [u8; AES_BLOCK_LEN], round: usize) {
        let base = 4 * round;
        for c in 0..4 {
            let w = self.rk[base + c];
            for r in 0..4 { b[4 * c + r] ^= w[r]; }
        }
    }
}

/// Substitute every byte of the state. # C: O(1)
fn sub_bytes(b: &mut [u8; AES_BLOCK_LEN]) {
    for x in b.iter_mut() { *x = sub_byte(*x); }
}

/// Rotate state row `r` left by `r` positions. The state is column-major, so
/// row `r` is the bytes at indices `r`, `r+4`, `r+8`, `r+12`. # C: O(1)
fn shift_rows(b: &mut [u8; AES_BLOCK_LEN]) {
    let s = *b;
    for r in 1..4 {
        for c in 0..4 { b[4 * c + r] = s[4 * ((c + r) % 4) + r]; }
    }
}

/// Mix each state column by the fixed field matrix. # C: O(1)
fn mix_columns(b: &mut [u8; AES_BLOCK_LEN]) {
    for c in 0..4 {
        let i = 4 * c;
        let a0 = b[i]; let a1 = b[i + 1]; let a2 = b[i + 2]; let a3 = b[i + 3];
        let x = a0 ^ a1 ^ a2 ^ a3;
        b[i]     = a0 ^ x ^ xtime(a0 ^ a1);
        b[i + 1] = a1 ^ x ^ xtime(a1 ^ a2);
        b[i + 2] = a2 ^ x ^ xtime(a2 ^ a3);
        b[i + 3] = a3 ^ x ^ xtime(a3 ^ a0);
    }
}
