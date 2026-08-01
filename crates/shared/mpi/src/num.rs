// The `Mpi` value: a non-negative integer held as base-2^64 limbs, least
// significant first, with NO zero high limb (the normalization invariant every
// other module restores before returning).

use alloc::vec::Vec;
use core::cmp::Ordering;

/// Bytes per limb — the export width, and the granularity a value's reported
/// size is rounded up to.
pub const LIMB_BYTES: usize = 8;
/// Bits per limb.
pub const LIMB_BITS: u32 = 64;

/// Arbitrary-precision non-negative integer.
#[derive(Clone, Debug, Default)]
pub struct Mpi {
    /// Base-2^64 limbs, least significant first, no trailing zero limb.
    pub(crate) d: Vec<u64>,
}

impl Mpi {
    /// Zero — the empty limb vector, so `is_zero` and `limbs() == 0` agree.
    /// # C: O(1)
    pub fn zero() -> Self { Self { d: Vec::new() } }

    /// # C: O(1)
    pub fn from_u64(v: u64) -> Self {
        if v == 0 { Self::zero() } else { Self { d: alloc::vec![v] } }
    }

    /// Import a big-endian byte string as a non-negative integer. Leading zero
    /// bytes carry no value and are dropped, so the imported value's reported
    /// size reflects the number, not the width the caller happened to send.
    /// # C: O(n)
    pub fn from_be_bytes(b: &[u8]) -> Self {
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        let b = &b[start..];
        let mut d: Vec<u64> = Vec::with_capacity(b.len().div_ceil(LIMB_BYTES));
        let mut i = b.len();
        while i > 0 {
            let lo = i.saturating_sub(LIMB_BYTES);
            let mut limb: u64 = 0;
            for &byte in &b[lo..i] { limb = (limb << 8) | byte as u64; }
            d.push(limb);
            i = lo;
        }
        let mut v = Self { d };
        v.normalize();
        v
    }

    /// Export as exactly `width` big-endian bytes, zero-padded on the left.
    /// `None` when the value does not fit — the caller must not silently
    /// truncate a modular result. # C: O(width)
    pub fn to_be_bytes(&self, width: usize) -> Option<Vec<u8>> {
        if self.byte_len() > width { return None; }
        let mut out = alloc::vec![0u8; width];
        let mut pos = width;
        for &limb in &self.d {
            for k in 0..LIMB_BYTES {
                if pos == 0 { break; }
                pos -= 1;
                out[pos] = (limb >> (8 * k)) as u8;
            }
        }
        Some(out)
    }

    /// Significant limb count. # C: O(1)
    pub fn limbs(&self) -> usize { self.d.len() }

    /// The size a value occupies in whole limbs, in bytes — `limbs() * 8`.
    /// This is the width Diffie-Hellman reports as its output size, so it is
    /// rounded up to a limb rather than being the minimal byte length.
    /// # C: O(1)
    pub fn limb_size(&self) -> usize { self.d.len() * LIMB_BYTES }

    /// Minimal number of bytes needed to hold the value (0 for zero).
    /// # C: O(1)
    pub fn byte_len(&self) -> usize { (self.bit_len() as usize).div_ceil(8) }

    /// Position of the highest set bit plus one; 0 for zero. # C: O(1)
    pub fn bit_len(&self) -> u32 {
        match self.d.last() {
            None => 0,
            Some(&top) => (self.d.len() as u32 - 1) * LIMB_BITS + (LIMB_BITS - top.leading_zeros()),
        }
    }

    /// Bit `i`, counted from the least significant. # C: O(1)
    pub fn bit(&self, i: u32) -> bool {
        let limb = (i / LIMB_BITS) as usize;
        match self.d.get(limb) { Some(&v) => (v >> (i % LIMB_BITS)) & 1 == 1, None => false }
    }

    /// # C: O(1)
    pub fn is_zero(&self) -> bool { self.d.is_empty() }

    /// # C: O(1)
    pub fn is_one(&self) -> bool { self.d.len() == 1 && self.d[0] == 1 }

    /// Drop zero high limbs, restoring the representation invariant.
    /// # C: O(n)
    pub(crate) fn normalize(&mut self) {
        while self.d.last() == Some(&0) { self.d.pop(); }
    }

    /// Build from raw limbs (least significant first), normalizing.
    /// # C: O(n)
    pub(crate) fn from_limbs(d: Vec<u64>) -> Self {
        let mut v = Self { d };
        v.normalize();
        v
    }
}

impl PartialEq for Mpi {
    fn eq(&self, other: &Self) -> bool { self.d == other.d }
}
impl Eq for Mpi {}

impl Ord for Mpi {
    /// Magnitude comparison: longer normalized limb vector is larger, else
    /// compare limbs from the top down. # C: O(n)
    fn cmp(&self, other: &Self) -> Ordering {
        if self.d.len() != other.d.len() { return self.d.len().cmp(&other.d.len()); }
        for i in (0..self.d.len()).rev() {
            match self.d[i].cmp(&other.d[i]) { Ordering::Equal => continue, o => return o }
        }
        Ordering::Equal
    }
}
impl PartialOrd for Mpi {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
