// Modular exponentiation — left-to-right square-and-multiply, reducing after
// every step so no intermediate exceeds twice the modulus width.
//
// The exponent here is a Diffie-Hellman private value or an RSA private
// exponent, so the loop is written to take the same number of squarings for
// every exponent of a given bit length; only the multiply is data-dependent.
// A window method would leak the same bits faster, so the plain square-and-
// multiply stays.

use crate::num::Mpi;

impl Mpi {
    /// `self^exp mod m`, or `None` when `m` is zero (undefined). A modulus of
    /// one yields zero for every input, and an exponent of zero yields
    /// `1 mod m`, both of which fall out of the loop below rather than being
    /// special-cased. # C: O(bits(exp) * len(m)^2)
    pub fn powm(&self, exp: &Self, m: &Self) -> Option<Self> {
        if m.is_zero() { return None; }
        let one = Self::from_u64(1);
        let mut result = one.rem(m).expect("modulus proven non-zero above");
        let base = self.rem(m).expect("modulus proven non-zero above");
        if base.is_zero() && !exp.is_zero() { return Some(Self::zero()); }
        let bits = exp.bit_len();
        for i in (0..bits).rev() {
            result = result.mul(&result).rem(m).expect("modulus proven non-zero above");
            if exp.bit(i) {
                result = result.mul(&base).rem(m).expect("modulus proven non-zero above");
            }
        }
        Some(result)
    }
}
