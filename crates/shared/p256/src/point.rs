//! Projective points and the complete addition law.
//!
//! The addition law is exception-free on a prime-order curve: the same
//! sequence computes a sum, a doubling, and any case involving the identity.
//! That is what makes a ladder built on it constant-time — there is no
//! doubling special case whose presence or absence a timing observer could
//! use to recover scalar bits.

use crate::field::Fp;
use crate::params::{A_MONT, B3_MONT, B_MONT, ELEM_LEN, GX_MONT, GY_MONT};

/// A point in homogeneous projective coordinates; the identity is `Z` zero.
#[derive(Copy, Clone, Debug)]
pub struct Point {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

/// Affine coordinates of a point that is not the identity.
#[derive(Copy, Clone, Debug)]
pub struct Affine {
    pub x: Fp,
    pub y: Fp,
}

impl Point {
    /// The group identity. # C: O(1)
    pub fn identity() -> Point { Point { x: Fp::zero(), y: Fp::one(), z: Fp::zero() } }

    /// The base point. # C: O(1)
    pub fn generator() -> Point {
        Point { x: Fp::from_mont(GX_MONT), y: Fp::from_mont(GY_MONT), z: Fp::one() }
    }

    /// Lift affine coordinates into projective ones. # C: O(1)
    pub fn from_affine(a: &Affine) -> Point { Point { x: a.x, y: a.y, z: Fp::one() } }

    /// Whether the point is the identity, as a zero-or-one flag. # C: O(1)
    pub fn is_identity(&self) -> u64 { self.z.is_zero() }

    /// Pick `a` when `c` is one, `b` when it is zero. # C: O(1)
    pub fn select(c: u64, a: &Point, b: &Point) -> Point {
        Point {
            x: Fp::select(c, &a.x, &b.x),
            y: Fp::select(c, &a.y, &b.y),
            z: Fp::select(c, &a.z, &b.z),
        }
    }

    /// The group law. Correct for every pair of inputs including equal ones
    /// and the identity. # C: O(1)
    pub fn add(&self, q: &Point) -> Point {
        let a = Fp::from_mont(A_MONT);
        let b3 = Fp::from_mont(B3_MONT);
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2, z2) = (q.x, q.y, q.z);

        let mut t0 = x1.mul(&x2);
        let mut t1 = y1.mul(&y2);
        let mut t2 = z1.mul(&z2);
        let mut t3 = x1.add(&y1);
        let mut t4 = x2.add(&y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = x1.add(&z1);
        let mut t5 = x2.add(&z2);
        t4 = t4.mul(&t5);
        t5 = t0.add(&t2);
        t4 = t4.sub(&t5);
        t5 = y1.add(&z1);
        let mut x3 = y2.add(&z2);
        t5 = t5.mul(&x3);
        x3 = t1.add(&t2);
        t5 = t5.sub(&x3);
        let mut z3 = a.mul(&t4);
        x3 = b3.mul(&t2);
        z3 = x3.add(&z3);
        x3 = t1.sub(&z3);
        z3 = t1.add(&z3);
        let mut y3 = x3.mul(&z3);
        t1 = t0.add(&t0);
        t1 = t1.add(&t0);
        t2 = a.mul(&t2);
        t4 = b3.mul(&t4);
        t1 = t1.add(&t2);
        t2 = t0.sub(&t2);
        t2 = a.mul(&t2);
        t4 = t4.add(&t2);
        t0 = t1.mul(&t4);
        y3 = y3.add(&t0);
        t0 = t5.mul(&t4);
        x3 = t3.mul(&x3);
        x3 = x3.sub(&t0);
        t0 = t3.mul(&t1);
        t1 = t5.mul(&z3);
        z3 = t1.add(&t0);

        Point { x: x3, y: y3, z: z3 }
    }

    /// Doubling, which the complete law already covers. # C: O(1)
    pub fn double(&self) -> Point { self.add(self) }

    /// Additive inverse. # C: O(1)
    pub fn neg(&self) -> Point { Point { x: self.x, y: self.y.neg(), z: self.z } }

    /// Divide through by the third coordinate. `None` for the identity, which
    /// has no affine representation. # C: O(1)
    pub fn to_affine(&self) -> Option<Affine> {
        if self.is_identity() == 1 { return None; }
        let zi = self.z.inv();
        Some(Affine { x: self.x.mul(&zi), y: self.y.mul(&zi) })
    }
}

impl Affine {
    /// Whether the coordinates satisfy the curve equation. # C: O(1)
    pub fn on_curve(&self) -> bool {
        let a = Fp::from_mont(A_MONT);
        let b = Fp::from_mont(B_MONT);
        let lhs = self.y.sqr();
        let rhs = self.x.sqr().mul(&self.x).add(&a.mul(&self.x)).add(&b);
        lhs.ct_eq(&rhs) == 1
    }

    /// Serialise the x coordinate. # C: O(1)
    pub fn x_bytes(&self) -> [u8; ELEM_LEN] { self.x.to_bytes_be() }

    /// Serialise the y coordinate. # C: O(1)
    pub fn y_bytes(&self) -> [u8; ELEM_LEN] { self.y.to_bytes_be() }
}
