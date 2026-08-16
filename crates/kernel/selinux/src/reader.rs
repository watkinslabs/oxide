// Little-endian cursor over a binary policy image.
//
// Every field of the policy image is little-endian regardless of host byte
// order, so all reads go through here. A short read is a policy error, never
// a panic: a truncated or hostile image must be rejected, not trusted.

use crate::error::{Error, Result};

/// Sequential little-endian reader over a policy image.
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Reader positioned at the start of an image. # C: O(1)
    pub const fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }

    /// Bytes consumed so far. # C: O(1)
    pub const fn position(&self) -> usize { self.pos }

    /// Bytes not yet consumed. # C: O(1)
    pub const fn remaining(&self) -> usize { self.bytes.len() - self.pos }

    /// Whether the whole image has been consumed. # C: O(1)
    pub const fn at_end(&self) -> bool { self.pos == self.bytes.len() }

    /// Next `n` bytes as a borrowed slice. # C: O(1)
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.bytes.len() { return Err(Error::Truncated); }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Next unsigned 32-bit field. # C: O(1)
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Next unsigned 64-bit field. # C: O(1)
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Next unsigned 16-bit field. # C: O(1)
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Next unsigned 8-bit field. # C: O(1)
    pub fn u8(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }

    /// Next `n` unsigned 32-bit fields into a caller array. # C: O(n)
    pub fn u32_array<const N: usize>(&mut self) -> Result<[u32; N]> {
        let mut out = [0u32; N];
        for slot in out.iter_mut() { *slot = self.u32()?; }
        Ok(out)
    }

    /// Next `len` bytes as a string, rejecting non-UTF-8. # C: O(len)
    ///
    /// Policy symbol names are ASCII by construction; anything else is a
    /// malformed image and is refused rather than lossily converted.
    pub fn string(&mut self, len: usize) -> Result<&'a str> {
        core::str::from_utf8(self.take(len)?).map_err(|_| Error::Malformed)
    }

    /// Length-prefixed string whose `u32` length was already read. # C: O(len)
    pub fn string_of(&mut self, len: u32) -> Result<&'a str> {
        if len as usize > self.remaining() { return Err(Error::Truncated); }
        self.string(len as usize)
    }
}
