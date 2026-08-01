// Addition and subtraction. Subtraction is `checked_sub`: a borrow out of the
// top means the result would be negative, which this crate has no
// representation for, so it is an absence rather than a wrapped value.

use alloc::vec::Vec;

use crate::num::Mpi;

impl Mpi {
    /// # C: O(max(len))
    pub fn add(&self, other: &Self) -> Self {
        let n = core::cmp::max(self.d.len(), other.d.len());
        let mut out: Vec<u64> = Vec::with_capacity(n + 1);
        let mut carry: u128 = 0;
        for i in 0..n {
            let a = *self.d.get(i).unwrap_or(&0) as u128;
            let b = *other.d.get(i).unwrap_or(&0) as u128;
            let s = a + b + carry;
            out.push(s as u64);
            carry = s >> 64;
        }
        out.push(carry as u64);
        Self::from_limbs(out)
    }

    /// `self - other`, or `None` when `other > self`. # C: O(max(len))
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self < other { return None; }
        let mut out: Vec<u64> = Vec::with_capacity(self.d.len());
        let mut borrow: i128 = 0;
        for i in 0..self.d.len() {
            let a = self.d[i] as i128;
            let b = *other.d.get(i).unwrap_or(&0) as i128;
            let t = a - b - borrow;
            out.push(t as u64);
            borrow = if t < 0 { 1 } else { 0 };
        }
        Some(Self::from_limbs(out))
    }
}
