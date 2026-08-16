//! The AES substitution table and the field arithmetic it is derived from.
//!
//! The table is computed at compile time from its definition — multiplicative
//! inverse in the field, then the affine transform — so no 256-entry literal
//! has to be transcribed correctly. The published table values are asserted in
//! the tests, which is the check that the derivation is right.

use crate::params::{GF_POLY_REDUCE, SBOX_AFFINE_CONST};

/// Double in the AES field: shift left, reduce by the field polynomial when
/// the shift carried out of the byte. # C: O(1)
pub const fn xtime(a: u8) -> u8 {
    let carried = a & 0x80 != 0;
    let shifted = a << 1;
    if carried { shifted ^ GF_POLY_REDUCE } else { shifted }
}

/// Multiply in the AES field by shift-and-add over the bits of `b`. # C: O(1)
pub const fn gmul(a: u8, b: u8) -> u8 {
    let mut x = a;
    let mut y = b;
    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        if y & 1 != 0 { r ^= x; }
        y >>= 1;
        x = xtime(x);
        i += 1;
    }
    r
}

/// Multiplicative inverse in the AES field, with zero mapped to zero as the
/// S-box definition requires. Computed as `a^254`. # C: O(1)
pub const fn ginv(a: u8) -> u8 {
    if a == 0 { return 0; }
    let mut r = 1u8;
    let mut i = 0;
    while i < 254 {
        r = gmul(r, a);
        i += 1;
    }
    r
}

/// One S-box entry: field inverse, then the affine transform. # C: O(1)
pub const fn sbox_of(a: u8) -> u8 {
    let x = ginv(a);
    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4)
      ^ SBOX_AFFINE_CONST
}

const fn build_sbox() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = sbox_of(i as u8);
        i += 1;
    }
    t
}

/// The AES substitution table. Indexing it with a key-dependent byte is a
/// cache-timing side channel; see the crate note.
pub static SBOX: [u8; 256] = build_sbox();

/// Substitute one byte. # C: O(1)
pub fn sub_byte(a: u8) -> u8 { SBOX[a as usize] }
