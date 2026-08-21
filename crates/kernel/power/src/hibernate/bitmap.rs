//! Bounded dense membership metadata for image PFNs and block locators.

extern crate alloc;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Bounds, NoMem }

/// Fixed-capacity bit membership owner.
pub struct Bitmap { words: Vec<u64>, limit: u64 }

impl Bitmap {
    /// Allocate complete membership capacity before the owner becomes live. # C: O(limit / 64)
    pub fn new(limit: u64) -> Result<Self, Error> {
        let count = usize::try_from(limit.div_ceil(u64::BITS as u64)).map_err(|_| Error::NoMem)?;
        let mut words = Vec::new();
        words.try_reserve_exact(count).map_err(|_| Error::NoMem)?;
        words.resize(count, 0);
        Ok(Self { words, limit })
    }

    /// Test one in-range member. # C: O(1)
    pub fn contains(&self, index: u64) -> bool {
        index < self.limit && self.words[(index >> 6) as usize] & (1u64 << (index & 63)) != 0
    }

    /// Insert one in-range member, returning false for a duplicate. # C: O(1)
    pub fn claim(&mut self, index: u64) -> Result<bool, Error> {
        if index >= self.limit { return Err(Error::Bounds); }
        let word = &mut self.words[(index >> 6) as usize];
        let bit = 1u64 << (index & 63);
        let fresh = *word & bit == 0;
        *word |= bit;
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_duplicates_and_word_edges_are_exact() {
        let mut bitmap = Bitmap::new(129).unwrap();
        for bit in [0, 63, 64, 128] {
            assert!(!bitmap.contains(bit));
            assert_eq!(bitmap.claim(bit), Ok(true));
            assert!(bitmap.contains(bit));
            assert_eq!(bitmap.claim(bit), Ok(false));
        }
        assert_eq!(bitmap.claim(129), Err(Error::Bounds));
        assert!(!bitmap.contains(u64::MAX));
    }
}
