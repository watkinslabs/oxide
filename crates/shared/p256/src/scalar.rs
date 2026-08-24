//! Scalar multiplication.
//!
//! One iteration per scalar bit, each performing a doubling and an addition
//! whatever the bit is, with the result chosen by arithmetic mask. The
//! operation sequence and the memory access pattern are identical for every
//! scalar, so neither the bit pattern nor the bit count is observable.

use crate::field::mask_of;
use crate::params::{ELEM_LEN, LIMBS, N, SCALAR_BITS};
use crate::point::Point;

/// A scalar as limbs, least significant first.
#[derive(Copy, Clone, Debug)]
pub struct Scalar(pub [u64; LIMBS]);

impl Scalar {
    /// Interpret 32 big-endian bytes as a scalar without range checking.
    /// # C: O(1)
    pub fn from_bytes_be(b: &[u8; ELEM_LEN]) -> Scalar {
        let mut v = [0u64; LIMBS];
        for i in 0..LIMBS {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[ELEM_LEN - 8 * (i + 1)..ELEM_LEN - 8 * i]);
            v[i] = u64::from_be_bytes(w);
        }
        Scalar(v)
    }

    /// Serialise as 32 big-endian bytes. # C: O(1)
    pub fn to_bytes_be(&self) -> [u8; ELEM_LEN] {
        let mut out = [0u8; ELEM_LEN];
        for i in 0..LIMBS {
            out[ELEM_LEN - 8 * (i + 1)..ELEM_LEN - 8 * i]
                .copy_from_slice(&self.0[i].to_be_bytes());
        }
        out
    }

    /// Whether the scalar is zero. # C: O(1)
    pub fn is_zero(&self) -> bool { self.0.iter().all(|l| *l == 0) }

    /// Whether the scalar is below the group order, which together with being
    /// nonzero is what makes it a usable private key. # C: O(1)
    pub fn in_range(&self) -> bool {
        let mut borrow = 0u128;
        for i in 0..LIMBS {
            let z = (self.0[i] as u128).wrapping_sub(N[i] as u128).wrapping_sub(borrow);
            borrow = (z >> 127) & 1;
        }
        borrow == 1 && !self.is_zero()
    }

    /// Bit `i` of the scalar as a zero-or-one flag. # C: O(1)
    pub fn bit(&self, i: usize) -> u64 { (self.0[i / 64] >> (i % 64)) & 1 }

    /// Reduce a 32-byte integer modulo the group order. # C: O(256)
    pub fn from_bytes_reduced(b: &[u8; ELEM_LEN]) -> Scalar {
        let mut r = Scalar([0; LIMBS]);
        let v = Scalar::from_bytes_be(b);
        for i in (0..SCALAR_BITS).rev() {
            r = r.double_mod();
            r = r.add_mod(&Scalar::select(v.bit(i), &Scalar::one(), &Scalar::zero()));
        }
        r
    }

    /// The zero scalar. # C: O(1)
    pub const fn zero() -> Scalar { Scalar([0; LIMBS]) }

    /// The one scalar. # C: O(1)
    pub const fn one() -> Scalar { Scalar([1, 0, 0, 0]) }

    /// Select a scalar without branching on its value. # C: O(1)
    pub fn select(c: u64, a: &Scalar, b: &Scalar) -> Scalar {
        let m = mask_of(c);
        let mut r = [0; LIMBS];
        for i in 0..LIMBS { r[i] = (a.0[i] & m) | (b.0[i] & !m); }
        Scalar(r)
    }

    /// Add modulo the group order. # C: O(1)
    pub fn add_mod(&self, o: &Scalar) -> Scalar {
        let mut r = [0; LIMBS];
        let mut carry = 0u128;
        for i in 0..LIMBS {
            let z = self.0[i] as u128 + o.0[i] as u128 + carry;
            r[i] = z as u64;
            carry = z >> 64;
        }
        let mut d = [0; LIMBS];
        let mut borrow = 0u128;
        for i in 0..LIMBS {
            let z = (r[i] as u128).wrapping_sub(N[i] as u128).wrapping_sub(borrow);
            d[i] = z as u64;
            borrow = (z >> 127) & 1;
        }
        Scalar::select(((carry | (borrow ^ 1)) & 1) as u64, &Scalar(d), &Scalar(r))
    }

    /// Double modulo the group order. # C: O(1)
    pub fn double_mod(&self) -> Scalar { self.add_mod(self) }

    /// Multiply modulo the group order using a fixed 256-step ladder. # C: O(256)
    pub fn mul_mod(&self, o: &Scalar) -> Scalar {
        let mut r = Scalar::zero();
        for i in (0..SCALAR_BITS).rev() {
            r = r.double_mod();
            r = r.add_mod(&Scalar::select(o.bit(i), self, &Scalar::zero()));
        }
        r
    }

    /// Invert modulo the group order by Fermat exponentiation. # C: O(65536)
    pub fn inv_mod(&self) -> Scalar {
        let mut r = Scalar::one();
        let exp = Scalar::from_bytes_be(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
        ]);
        for i in (0..SCALAR_BITS).rev() {
            r = r.mul_mod(&r);
            r = Scalar::select(exp.bit(i), &r.mul_mod(self), &r);
        }
        r
    }
}

/// Multiply a point by a scalar. # C: O(1)
pub fn mul(k: &Scalar, p: &Point) -> Point {
    let mut acc = Point::identity();
    for i in (0..SCALAR_BITS).rev() {
        acc = acc.double();
        let sum = acc.add(p);
        acc = Point::select(k.bit(i), &sum, &acc);
    }
    acc
}

/// Multiply the base point by a scalar. # C: O(1)
pub fn mul_base(k: &Scalar) -> Point { mul(k, &Point::generator()) }
