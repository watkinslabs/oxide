//! The data unit number: which unit of a key's stream a data unit is.
//!
//! It is a counter, not an address. One data unit of a request advances it by
//! one, and the IV a construction takes is the counter's limbs written
//! little-endian — so a number wider than one word is a multi-limb integer,
//! carried by hand, and the low limb is the low bytes of the IV.
//!
//! Two rules about it decide correctness and nothing else can recover from
//! getting them wrong:
//!
//! - Two runs of data units may share ONE request only when the second run's
//!   number is exactly the first's plus the units before it. A request that
//!   merged a discontiguous run would encrypt the second run under the first
//!   run's continuation, which decrypts to noise and reports nothing.
//! - A number that WRAPS through zero is not contiguous with what preceded
//!   it, even though the arithmetic says it is. Wrapping means two different
//!   data units of one key share a number, and the second silently overwrites
//!   the first's keystream position.

/// Widest IV any inline mode takes.
pub const MAX_IV_SIZE: usize = 32;

/// Limbs a data unit number is carried in — the widest IV, in 64-bit words.
pub const DUN_LIMBS: usize = MAX_IV_SIZE / 8;

/// A data unit number, low limb first.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Dun([u64; DUN_LIMBS]);

impl Dun {
    /// The number zero. # C: O(1)
    pub const ZERO: Dun = Dun([0; DUN_LIMBS]);

    /// A number from its limbs, low limb first. # C: O(1)
    pub const fn from_limbs(limbs: [u64; DUN_LIMBS]) -> Dun { Dun(limbs) }

    /// A number that fits one limb. # C: O(1)
    pub const fn from_u64(v: u64) -> Dun {
        let mut l = [0u64; DUN_LIMBS];
        l[0] = v;
        Dun(l)
    }

    /// The limbs, low limb first. # C: O(1)
    pub const fn limbs(&self) -> &[u64; DUN_LIMBS] { &self.0 }

    /// Advance by `inc` data units, carrying between limbs.
    ///
    /// A carry out of the top limb is DISCARDED, which is the wrap this type's
    /// contiguity rule exists to catch: the number itself has nowhere wider to
    /// go, so the only defence is refusing to put the wrapped run in the same
    /// request as what preceded it.
    /// # C: O(DUN_LIMBS)
    pub fn increment(&mut self, inc: u64) {
        let mut carry = inc;
        for limb in self.0.iter_mut() {
            if carry == 0 { break; }
            let (sum, overflowed) = limb.overflowing_add(carry);
            *limb = sum;
            carry = u64::from(overflowed);
        }
    }

    /// The same number advanced by `inc`. # C: O(DUN_LIMBS)
    pub fn advanced(mut self, inc: u64) -> Dun { self.increment(inc); self }

    /// Whether `next` is exactly this number plus `units`, without wrapping.
    ///
    /// The wrap check is the whole point of returning at the end rather than
    /// on the last limb: a carry that leaves the top limb means the two runs
    /// only LOOK adjacent, and merging them would reuse a keystream position.
    /// # C: O(DUN_LIMBS)
    pub fn is_contiguous(&self, units: u64, next: &Dun) -> bool {
        let mut carry = units;
        for i in 0..DUN_LIMBS {
            let (sum, overflowed) = self.0[i].overflowing_add(carry);
            if sum != next.0[i] { return false; }
            carry = u64::from(overflowed);
        }
        carry == 0
    }

    /// The IV bytes a construction takes: every limb little-endian, low limb
    /// first, zero-padded to the widest IV. A mode narrower than that reads
    /// only the low bytes. # C: O(DUN_LIMBS)
    pub fn to_iv(&self) -> [u8; MAX_IV_SIZE] {
        let mut iv = [0u8; MAX_IV_SIZE];
        for (i, limb) in self.0.iter().enumerate() {
            iv[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        iv
    }
}
