// Bounds-checked big-endian reads. Every read either advances the cursor by
// exactly the field width or fails; there is no path that returns a value
// built from bytes past the end of the buffer.

use super::error::CodecError;

/// Cursor over a response body.
pub struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    /// Cursor at the start of `buf`. # C: O(1)
    pub fn new(buf: &'a [u8]) -> Self { Reader { buf, off: 0 } }

    /// Bytes not yet consumed. # C: O(1)
    pub fn remaining(&self) -> usize { self.buf.len() - self.off }

    /// Current offset from the start of the buffer. # C: O(1)
    pub fn offset(&self) -> usize { self.off }

    /// Whether the cursor has consumed the whole buffer. # C: O(1)
    pub fn is_empty(&self) -> bool { self.remaining() == 0 }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n { return Err(CodecError::Truncated { need: n, have: self.remaining() }); }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    /// Next byte. # C: O(1)
    pub fn u8(&mut self) -> Result<u8, CodecError> { Ok(self.take(1)?[0]) }

    /// Next 16-bit big-endian word. # C: O(1)
    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// Next 32-bit big-endian word. # C: O(1)
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Next 64-bit big-endian word. # C: O(1)
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let s = self.take(8)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(s);
        Ok(u64::from_be_bytes(v))
    }

    /// Next `n` bytes. # C: O(1)
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> { self.take(n) }

    /// A 16-bit-counted byte string. # C: O(1)
    pub fn sized_u16(&mut self) -> Result<&'a [u8], CodecError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}
