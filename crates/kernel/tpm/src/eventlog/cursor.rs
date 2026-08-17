// Bounds-checked little-endian cursor over a firmware-supplied log. Every
// read is length-checked against the buffer, because the count and size
// fields that drive the walk are attacker-influenced data, not structure.

use super::error::LogError;

/// Cursor over log bytes.
pub struct LeCursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> LeCursor<'a> {
    /// Cursor at the start of `buf`. # C: O(1)
    pub fn new(buf: &'a [u8]) -> Self { LeCursor { buf, off: 0 } }

    /// Bytes not yet consumed. # C: O(1)
    pub fn remaining(&self) -> usize { self.buf.len() - self.off }

    /// Bytes consumed so far. # C: O(1)
    pub fn offset(&self) -> usize { self.off }

    /// Advance without reading. # C: O(1)
    pub fn skip(&mut self, n: usize) -> Result<(), LogError> { self.bytes(n).map(|_| ()) }

    /// Next `n` bytes. # C: O(1)
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], LogError> {
        if self.remaining() < n { return Err(LogError::Truncated { need: n, have: self.remaining() }); }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    /// Next byte. # C: O(1)
    pub fn u8(&mut self) -> Result<u8, LogError> { Ok(self.bytes(1)?[0]) }

    /// Next 16-bit little-endian word. # C: O(1)
    pub fn u16(&mut self) -> Result<u16, LogError> {
        let s = self.bytes(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Next 32-bit little-endian word. # C: O(1)
    pub fn u32(&mut self) -> Result<u32, LogError> {
        let s = self.bytes(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}
