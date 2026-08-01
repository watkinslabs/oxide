// Truncated division with remainder — Knuth algorithm D over base-2^64 limbs.
//
// The divisor is scaled so its top limb has bit 63 set, which is what bounds
// the trial quotient digit to at most two corrections; the remainder is scaled
// back by the same amount at the end. The "add back" branch fires for roughly
// one divisor in 2^64 and is exercised deliberately by the tests rather than
// left to chance.

use alloc::vec::Vec;

use crate::num::{Mpi, LIMB_BITS};
use crate::shift::{shl_bits, shr_bits};

/// Base-2^64 limb mask on a 128-bit intermediate.
const LIMB_MASK: u128 = u64::MAX as u128;

impl Mpi {
    /// `(self / other, self % other)`, or `None` when `other` is zero.
    /// # C: O(len(self) * len(other))
    pub fn divmod(&self, other: &Self) -> Option<(Self, Self)> {
        if other.is_zero() { return None; }
        if self < other { return Some((Self::zero(), self.clone())); }
        if other.d.len() == 1 { return Some(self.divmod_limb(other.d[0])); }
        Some(self.divmod_knuth(other))
    }

    /// `self % other`, or `None` when `other` is zero. # C: as `divmod`
    pub fn rem(&self, other: &Self) -> Option<Self> { self.divmod(other).map(|(_, r)| r) }

    /// Single-limb division — the common short case, and the one Knuth's
    /// algorithm cannot take because it indexes the divisor's second limb.
    /// # C: O(len)
    fn divmod_limb(&self, v: u64) -> (Self, Self) {
        let mut q: Vec<u64> = alloc::vec![0u64; self.d.len()];
        let mut r: u128 = 0;
        for i in (0..self.d.len()).rev() {
            let cur = (r << 64) | self.d[i] as u128;
            q[i] = (cur / v as u128) as u64;
            r = cur % v as u128;
        }
        (Self::from_limbs(q), Self::from_u64(r as u64))
    }

    /// # C: O(len(self) * len(other))
    fn divmod_knuth(&self, other: &Self) -> (Self, Self) {
        let n = other.d.len();
        let s = other.d[n - 1].leading_zeros();
        let mut v = shl_bits(&other.d, s);
        v.truncate(n); // the scaled divisor keeps exactly n limbs by construction
        let mut u = shl_bits(&self.d, s);
        if u.len() == self.d.len() { u.push(0); }
        let m = u.len() - 1 - n;
        let mut q: Vec<u64> = alloc::vec![0u64; m + 1];

        for j in (0..=m).rev() {
            let top = ((u[j + n] as u128) << 64) | u[j + n - 1] as u128;
            let mut qhat = top / v[n - 1] as u128;
            let mut rhat = top % v[n - 1] as u128;
            loop {
                let too_big = qhat > LIMB_MASK
                    || qhat * v[n - 2] as u128 > ((rhat << 64) | u[j + n - 2] as u128);
                if !too_big { break; }
                qhat -= 1;
                rhat += v[n - 1] as u128;
                if rhat > LIMB_MASK { break; }
            }

            // Multiply the divisor by the trial digit and subtract it out.
            let mut borrow: i128 = 0;
            let mut carry: u128 = 0;
            for i in 0..n {
                let p = qhat * v[i] as u128 + carry;
                carry = p >> 64;
                let t = u[i + j] as i128 - (p & LIMB_MASK) as i128 - borrow;
                u[i + j] = t as u64;
                borrow = if t < 0 { 1 } else { 0 };
            }
            let t = u[j + n] as i128 - carry as i128 - borrow;
            u[j + n] = t as u64;

            if t < 0 {
                // The trial digit was one too large: give back one divisor.
                q[j] = (qhat - 1) as u64;
                let mut c: u128 = 0;
                for i in 0..n {
                    let sum = u[i + j] as u128 + v[i] as u128 + c;
                    u[i + j] = sum as u64;
                    c = sum >> 64;
                }
                u[j + n] = (u[j + n] as u128 + c) as u64;
            } else {
                q[j] = qhat as u64;
            }
        }

        u.truncate(n);
        shr_bits(&mut u, s % LIMB_BITS);
        (Self::from_limbs(q), Self::from_limbs(u))
    }
}
