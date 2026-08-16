//! A bitmap: one bit per cluster in `$Bitmap`, one bit per record in the MFT's
//! own `$BITMAP` attribute.
//!
//! Both are the same structure over different units, so both are this module.
//! What differs is what a set bit means — an allocated cluster, or a record
//! that is in use — and neither may be inferred from anything else: a record
//! marked free whose bit is set is one a check will reclaim while a directory
//! still names it.

use alloc::vec::Vec;

use syscall::errno::Errno;

/// Bits in one byte.
const BITS_PER_BYTE: u64 = 8;

/// A bitmap held in memory.
pub struct Bitmap {
    bytes: Vec<u8>,
    /// Bits that mean anything. Bits past this are padding in the last byte
    /// and must never be handed out.
    bits: u64,
}

impl Bitmap {
    /// # C: O(1)
    pub fn new(bytes: Vec<u8>, bits: u64) -> Self { Self { bytes, bits } }

    /// The bitmap's bytes. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Bits the bitmap covers. # C: O(1)
    pub fn bits(&self) -> u64 { self.bits }

    /// Byte and bit within it, or `None` when the index is past the end.
    /// # C: O(1)
    fn position(&self, index: u64) -> Option<(usize, u8)> {
        if index >= self.bits { return None; }
        let byte = usize::try_from(index / BITS_PER_BYTE).ok()?;
        if byte >= self.bytes.len() { return None; }
        Some((byte, (index % BITS_PER_BYTE) as u8))
    }

    /// Whether `index` is in use. An index the bitmap does not cover reads as
    /// in use, so nothing hands it out. # C: O(1)
    pub fn is_set(&self, index: u64) -> bool {
        let Some((byte, bit)) = self.position(index) else { return true };
        self.bytes[byte] & (1 << bit) != 0
    }

    /// Claim `index`. # C: O(1)
    pub fn set(&mut self, index: u64) -> Result<(), Errno> {
        let (byte, bit) = self.position(index).ok_or(Errno::Eio)?;
        self.bytes[byte] |= 1 << bit;
        Ok(())
    }

    /// Release `index`. # C: O(1)
    pub fn clear(&mut self, index: u64) -> Result<(), Errno> {
        let (byte, bit) = self.position(index).ok_or(Errno::Eio)?;
        self.bytes[byte] &= !(1 << bit);
        Ok(())
    }

    /// The first free index at or after `from`, wrapping once to the start.
    /// # C: O(bits)
    pub fn find_free(&self, from: u64) -> Option<u64> {
        let start = if from < self.bits { from } else { 0 };
        for index in start..self.bits { if !self.is_set(index) { return Some(index); } }
        for index in 0..start { if !self.is_set(index) { return Some(index); } }
        None
    }

    /// The first run of `count` consecutive free indexes at or after `from`.
    ///
    /// A file laid down as one extent is one run in its runlist rather than
    /// `count` of them, and a runlist that no longer fits its record forces
    /// the attribute out into a second record.
    /// # C: O(bits)
    pub fn find_free_run(&self, from: u64, count: u64) -> Option<u64> {
        if count == 0 { return None; }
        let scan = |begin: u64, end: u64| -> Option<u64> {
            let mut run = 0u64;
            for index in begin..end {
                run = if self.is_set(index) { 0 } else { run + 1 };
                if run == count { return Some(index + 1 - count); }
            }
            None
        };
        let start = if from < self.bits { from } else { 0 };
        scan(start, self.bits).or_else(|| scan(0, start))
    }

    /// How many indexes are in use. # C: O(bits)
    pub fn used(&self) -> u64 { (0..self.bits).filter(|i| self.is_set(*i)).count() as u64 }

    /// Whether a whole run is free. # C: O(count)
    pub fn range_free(&self, index: u64, count: u64) -> bool {
        (0..count).all(|i| index.checked_add(i).is_some_and(|n| !self.is_set(n)))
    }

    /// Claim a run. # C: O(count)
    pub fn set_range(&mut self, index: u64, count: u64) -> Result<(), Errno> {
        for i in 0..count { self.set(index + i)?; }
        Ok(())
    }

    /// Release a run. # C: O(count)
    pub fn clear_range(&mut self, index: u64, count: u64) -> Result<(), Errno> {
        for i in 0..count { self.clear(index + i)?; }
        Ok(())
    }
}

/// Bytes a bitmap covering `bits` indexes occupies. # C: O(1)
pub fn bytes_for(bits: u64) -> u64 { bits.div_ceil(BITS_PER_BYTE) }

#[cfg(test)]
#[path = "tests/bitmap.rs"]
mod tests;
