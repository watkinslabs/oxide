// Schoolbook multiplication. Karatsuba would win above a few thousand bits;
// the operand sizes here (a 2048-bit modular exponentiation is ~3000 of these)
// sit below its crossover, and a second multiplication path would be a second
// thing to prove correct.

use alloc::vec::Vec;

use crate::num::Mpi;

impl Mpi {
    /// # C: O(len(self) * len(other))
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() { return Self::zero(); }
        let mut out: Vec<u64> = alloc::vec![0u64; self.d.len() + other.d.len()];
        for (i, &a) in self.d.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j, &b) in other.d.iter().enumerate() {
                let t = a as u128 * b as u128 + out[i + j] as u128 + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            let mut k = i + other.d.len();
            while carry != 0 {
                let t = out[k] as u128 + carry;
                out[k] = t as u64;
                carry = t >> 64;
                k += 1;
            }
        }
        Self::from_limbs(out)
    }
}
