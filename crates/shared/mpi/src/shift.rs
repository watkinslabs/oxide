// Limb-vector bit shifts. Division normalizes its divisor so the top limb has
// its high bit set (Knuth's `d` scaling) and un-normalizes the remainder
// afterwards; both directions live here rather than inside the division loop.

use alloc::vec::Vec;

use crate::num::{Mpi, LIMB_BITS};

/// Shift left by `s < 64` bits, growing the vector by one limb when the shift
/// carries out of the top. # C: O(n)
pub(crate) fn shl_bits(d: &[u64], s: u32) -> Vec<u64> {
    if s == 0 { return d.to_vec(); }
    let mut out: Vec<u64> = Vec::with_capacity(d.len() + 1);
    let mut carry: u64 = 0;
    for &limb in d {
        out.push((limb << s) | carry);
        carry = limb >> (LIMB_BITS - s);
    }
    out.push(carry);
    out
}

/// Shift right by `s < 64` bits in place. # C: O(n)
pub(crate) fn shr_bits(d: &mut [u64], s: u32) {
    if s == 0 { return; }
    let mut carry: u64 = 0;
    for i in (0..d.len()).rev() {
        let limb = d[i];
        d[i] = (limb >> s) | carry;
        carry = limb << (LIMB_BITS - s);
    }
}

impl Mpi {
    /// `self >> n`. # C: O(len + n/64)
    pub fn shr(&self, n: u32) -> Self {
        let whole = (n / LIMB_BITS) as usize;
        if whole >= self.d.len() { return Self::zero(); }
        let mut d = self.d[whole..].to_vec();
        shr_bits(&mut d, n % LIMB_BITS);
        Self::from_limbs(d)
    }

    /// `self << n`. # C: O(len + n/64)
    pub fn shl(&self, n: u32) -> Self {
        if self.is_zero() { return Self::zero(); }
        let whole = (n / LIMB_BITS) as usize;
        let mut d = alloc::vec![0u64; whole];
        d.extend_from_slice(&shl_bits(&self.d, n % LIMB_BITS));
        Self::from_limbs(d)
    }
}
