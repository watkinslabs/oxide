//! Arithmetic modulo the P-256 field prime.
//!
//! Values are held in Montgomery form. Every operation is branch-free on the
//! value: reductions are a conditional subtract driven by an arithmetic mask,
//! never an `if` on limb contents.

use crate::params::{ELEM_LEN, LIMBS, P, R, R2};

/// A field element, Montgomery form, limbs least significant first.
#[derive(Copy, Clone, Debug)]
pub struct Fp(pub [u64; LIMBS]);

/// All-ones when `c` is one, all-zeros when `c` is zero. # C: O(1)
pub fn mask_of(c: u64) -> u64 { 0u64.wrapping_sub(c) }

/// Add with carry out. # C: O(1)
fn adc(a: [u64; LIMBS], b: [u64; LIMBS]) -> ([u64; LIMBS], u64) {
    let mut r = [0u64; LIMBS];
    let mut carry = 0u128;
    for i in 0..LIMBS {
        let z = (a[i] as u128) + (b[i] as u128) + carry;
        r[i] = z as u64;
        carry = z >> 64;
    }
    (r, carry as u64)
}

/// Subtract with borrow out. # C: O(1)
fn sbb(a: [u64; LIMBS], b: [u64; LIMBS]) -> ([u64; LIMBS], u64) {
    let mut r = [0u64; LIMBS];
    let mut borrow = 0u128;
    for i in 0..LIMBS {
        let z = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow);
        r[i] = z as u64;
        borrow = (z >> 127) & 1;
    }
    (r, borrow as u64)
}

/// Pick `a` when `c` is one, `b` when it is zero, without branching. # C: O(1)
pub fn select(c: u64, a: [u64; LIMBS], b: [u64; LIMBS]) -> [u64; LIMBS] {
    let m = mask_of(c);
    let mut r = [0u64; LIMBS];
    for i in 0..LIMBS { r[i] = (a[i] & m) | (b[i] & !m); }
    r
}

/// Reduce a value below twice the prime, given the carry bit above the top
/// limb, by subtracting the prime when the value is at least the prime.
/// # C: O(1)
fn reduce_once(v: [u64; LIMBS], hi: u64) -> [u64; LIMBS] {
    let (d, borrow) = sbb(v, P);
    // Subtract when the extra bit is set (so the value certainly exceeds the
    // prime) or when the subtraction did not borrow (so it was at least it).
    select(hi | (borrow ^ 1), d, v)
}

/// Montgomery product of two limb arrays. # C: O(1)
fn mont_mul(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; LIMBS] {
    let mut t = [0u64; LIMBS + 2];
    for i in 0..LIMBS {
        let mut carry = 0u128;
        for j in 0..LIMBS {
            let z = (a[j] as u128) * (b[i] as u128) + (t[j] as u128) + carry;
            t[j] = z as u64;
            carry = z >> 64;
        }
        let z = (t[LIMBS] as u128) + carry;
        t[LIMBS] = z as u64;
        t[LIMBS + 1] = (z >> 64) as u64;

        // The negated inverse of the prime modulo 2^64 is one, so the
        // reduction multiplier is the low limb itself.
        let m = t[0] as u128;
        let mut carry = ((m * (P[0] as u128) + (t[0] as u128)) >> 64) as u128;
        for j in 1..LIMBS {
            let z = m * (P[j] as u128) + (t[j] as u128) + carry;
            t[j - 1] = z as u64;
            carry = z >> 64;
        }
        let z = (t[LIMBS] as u128) + carry;
        t[LIMBS - 1] = z as u64;
        t[LIMBS] = t[LIMBS + 1] + ((z >> 64) as u64);
    }
    reduce_once([t[0], t[1], t[2], t[3]], t[LIMBS])
}

impl Fp {
    /// The additive identity. # C: O(1)
    pub fn zero() -> Fp { Fp([0; LIMBS]) }

    /// The multiplicative identity. # C: O(1)
    pub fn one() -> Fp { Fp(R) }

    /// Wrap limbs already in Montgomery form. # C: O(1)
    pub fn from_mont(limbs: [u64; LIMBS]) -> Fp { Fp(limbs) }

    /// Sum modulo the prime. # C: O(1)
    pub fn add(&self, o: &Fp) -> Fp {
        let (s, carry) = adc(self.0, o.0);
        Fp(reduce_once(s, carry))
    }

    /// Difference modulo the prime. # C: O(1)
    pub fn sub(&self, o: &Fp) -> Fp {
        let (d, borrow) = sbb(self.0, o.0);
        let m = mask_of(borrow);
        let mut r = [0u64; LIMBS];
        let mut carry = 0u128;
        for i in 0..LIMBS {
            let z = (d[i] as u128) + ((P[i] & m) as u128) + carry;
            r[i] = z as u64;
            carry = z >> 64;
        }
        Fp(r)
    }

    /// Product modulo the prime. # C: O(1)
    pub fn mul(&self, o: &Fp) -> Fp { Fp(mont_mul(&self.0, &o.0)) }

    /// Square modulo the prime. # C: O(1)
    pub fn sqr(&self) -> Fp { self.mul(self) }

    /// Additive inverse modulo the prime. # C: O(1)
    pub fn neg(&self) -> Fp { Fp::zero().sub(self) }

    /// Multiplicative inverse, by raising to the prime minus two. The exponent
    /// is a curve constant, so the fixed chain leaks nothing about the value.
    /// Zero maps to zero. # C: O(1)
    pub fn inv(&self) -> Fp {
        // p - 2 = 2^256 - 2^224 + 2^192 + 2^96 - 3. Square-and-multiply over
        // its bits, most significant first.
        let exp: [u64; LIMBS] =
            [0xfffffffffffffffd, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001];
        let mut acc = Fp::one();
        let mut started = false;
        for i in (0..LIMBS).rev() {
            for bit in (0..64).rev() {
                if started { acc = acc.sqr(); }
                if (exp[i] >> bit) & 1 == 1 {
                    acc = if started { acc.mul(self) } else { *self };
                    started = true;
                }
            }
        }
        acc
    }

    /// Whether the element is zero, as a zero-or-one flag. # C: O(1)
    pub fn is_zero(&self) -> u64 {
        let mut acc = 0u64;
        for i in 0..LIMBS { acc |= self.0[i]; }
        nonzero_flag(acc) ^ 1
    }

    /// Whether two elements are equal, as a zero-or-one flag. # C: O(1)
    pub fn ct_eq(&self, o: &Fp) -> u64 {
        let mut acc = 0u64;
        for i in 0..LIMBS { acc |= self.0[i] ^ o.0[i]; }
        nonzero_flag(acc) ^ 1
    }

    /// Pick `a` when `c` is one, `b` when it is zero. # C: O(1)
    pub fn select(c: u64, a: &Fp, b: &Fp) -> Fp { Fp(select(c, a.0, b.0)) }

    /// Interpret 32 big-endian bytes as a residue, rejecting a value that is
    /// not already reduced. # C: O(1)
    pub fn from_bytes_be(b: &[u8; ELEM_LEN]) -> Option<Fp> {
        let mut v = [0u64; LIMBS];
        for i in 0..LIMBS {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[ELEM_LEN - 8 * (i + 1)..ELEM_LEN - 8 * i]);
            v[i] = u64::from_be_bytes(w);
        }
        let (_, borrow) = sbb(v, P);
        if borrow == 0 { return None; }
        Some(Fp(mont_mul(&v, &R2)))
    }

    /// Serialise as 32 big-endian bytes. # C: O(1)
    pub fn to_bytes_be(&self) -> [u8; ELEM_LEN] {
        let canonical = mont_mul(&self.0, &[1, 0, 0, 0]);
        let mut out = [0u8; ELEM_LEN];
        for i in 0..LIMBS {
            out[ELEM_LEN - 8 * (i + 1)..ELEM_LEN - 8 * i]
                .copy_from_slice(&canonical[i].to_be_bytes());
        }
        out
    }
}

/// One when the word is nonzero, zero when it is zero. # C: O(1)
pub fn nonzero_flag(x: u64) -> u64 { ((x | x.wrapping_neg()) >> 63) & 1 }
