// AES substitution tables. Both are derived at compile time from the field
// definition rather than transcribed, so a typo cannot introduce a table that
// is self-consistent but wrong: SBOX[x] = affine(x^-1) over GF(2^8) modulo
// x^8+x^4+x^3+x+1, with 0 mapped to 0; INV_SBOX is its exact inverse
// permutation. The known-answer tests pin the resulting cipher.

/// Reduction polynomial x^8+x^4+x^3+x+1, low 8 bits.
const POLY: u16 = 0x11b;

/// Carry-less multiply in GF(2^8).
const fn gmul(a: u8, b: u8) -> u8 {
    let (mut r, mut x, mut y) = (0u16, a as u16, b);
    let mut i = 0;
    while i < 8 {
        if y & 1 != 0 { r ^= x; }
        y >>= 1;
        x <<= 1;
        if x & 0x100 != 0 { x ^= POLY; }
        i += 1;
    }
    r as u8
}

/// Inverse table over GF(2^8), built from the powers of the generator 3:
/// x^-1 = g^(255 - log_g x) for x != 0, and 0^-1 is defined as 0.
const fn build_inv_field() -> [u8; 256] {
    let (mut exp, mut log) = ([0u8; 255], [0u8; 256]);
    let mut x = 1u8;
    let mut i = 0;
    while i < 255 { exp[i] = x; log[x as usize] = i as u8; x = gmul(x, 3); i += 1; }
    let mut t = [0u8; 256];
    let mut a = 1usize;
    while a < 256 { t[a] = exp[(255 - log[a] as usize) % 255]; a += 1; }
    t
}

const INV_FIELD: [u8; 256] = build_inv_field();

const fn ginv(a: u8) -> u8 { INV_FIELD[a as usize] }

const fn affine(b: u8) -> u8 {
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

const fn build_sbox() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 { t[i] = affine(ginv(i as u8)); i += 1; }
    t
}

const fn build_inv(s: &[u8; 256]) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 { t[s[i] as usize] = i as u8; i += 1; }
    t
}

pub(super) const SBOX: [u8; 256] = build_sbox();
pub(super) const INV_SBOX: [u8; 256] = build_inv(&SBOX);

/// Round constants, one per key-expansion round; 10 covers AES-128 (the
/// widest user), AES-256 consumes 7.
pub(super) const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Runtime GF(2^8) multiply, used by InvMixColumns.
pub(super) fn mul(a: u8, b: u8) -> u8 { gmul(a, b) }
