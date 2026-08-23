//! The AES arithmetic S-box and the field operations it is derived from.
//!
//! The substitution is computed from the field inverse and affine transform;
//! the runtime path does not index a table with key- or data-dependent bytes.

use crate::params::{GF_POLY_REDUCE, SBOX_AFFINE_CONST};

/// Double in the AES field: shift left, reduce by the field polynomial when
/// the shift carried out of the byte. # C: O(1)
pub const fn xtime(a: u8) -> u8 {
    let shifted = a << 1;
    let reduce = 0u8.wrapping_sub(a >> 7);
    shifted ^ (GF_POLY_REDUCE & reduce)
}

/// Multiply in the AES field with fixed-round, masked arithmetic. # C: O(1)
pub const fn gmul(a: u8, b: u8) -> u8 {
    let mut x = a;
    let mut y = b;
    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        let take = 0u8.wrapping_sub(y & 1);
        r ^= x & take;
        y >>= 1;
        x = xtime(x);
        i += 1;
    }
    r
}

/// Multiplicative inverse in the AES field, with zero mapped to zero as the
/// S-box definition requires. Computed as `a^254`. # C: O(1)
pub const fn ginv(a: u8) -> u8 {
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

/// Substitute one byte without a secret-indexed memory access. # C: O(1)
pub fn sub_byte(a: u8) -> u8 { sbox_of(a) }

/// Undo the affine map and take the field inverse. # C: O(1)
pub const fn inv_sbox_of(a: u8) -> u8 {
    let x = a.rotate_left(1) ^ a.rotate_left(3) ^ a.rotate_left(6) ^ 0x05;
    ginv(x)
}

/// Substitute one byte through the arithmetic inverse S-box. # C: O(1)
pub fn inv_sub_byte(a: u8) -> u8 { inv_sbox_of(a) }
