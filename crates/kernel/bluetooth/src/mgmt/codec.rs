//! Little-endian cursor pair every management record is read and written
//! through. A read past the end yields `None` rather than a partial value, and
//! a decoder that finishes with bytes still unread has been handed an over-long
//! payload — `Reader::done` is what makes that a refusal instead of silence.

use alloc::vec::Vec;

use crate::uapi::bt::{BdAddr, BDADDR_LEN};

/// Bounds-checked forward cursor over a wire payload.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start at the first byte of `buf`. # C: O(1)
    pub fn new(buf: &'a [u8]) -> Reader<'a> { Reader { buf, pos: 0 } }

    /// Bytes not yet consumed. # C: O(1)
    pub fn remaining(&self) -> usize { self.buf.len() - self.pos }

    /// Whether every byte has been consumed. A decoder returns its value only
    /// when this holds, so trailing bytes are an error. # C: O(1)
    pub fn done(&self) -> bool { self.pos == self.buf.len() }

    /// The unconsumed tail, for the variable-length records that follow a
    /// fixed prefix. # C: O(1)
    pub fn rest(&self) -> &'a [u8] { &self.buf[self.pos..] }

    /// Take `n` bytes. # C: O(1)
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() { return None; }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }

    /// Take `N` bytes as an owned array. # C: O(N)
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Some(a)
    }

    /// # C: O(1)
    pub fn u8(&mut self) -> Option<u8> { Some(self.take(1)?[0]) }

    /// # C: O(1)
    pub fn i8(&mut self) -> Option<i8> { Some(self.u8()? as i8) }

    /// # C: O(1)
    pub fn u16(&mut self) -> Option<u16> { Some(u16::from_le_bytes(self.array::<2>()?)) }

    /// # C: O(1)
    pub fn u32(&mut self) -> Option<u32> { Some(u32::from_le_bytes(self.array::<4>()?)) }

    /// # C: O(1)
    pub fn u64(&mut self) -> Option<u64> { Some(u64::from_le_bytes(self.array::<8>()?)) }

    /// Take a device address in wire order. # C: O(1)
    pub fn addr(&mut self) -> Option<BdAddr> { Some(BdAddr(self.array::<BDADDR_LEN>()?)) }
}

/// Append-only little-endian builder.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// # C: O(1)
    pub fn new() -> Writer { Writer { out: Vec::new() } }

    /// Reserve `n` bytes up front for a record of known width. # C: O(n)
    pub fn with_capacity(n: usize) -> Writer { Writer { out: Vec::with_capacity(n) } }

    /// Bytes written so far. # C: O(1)
    pub fn len(&self) -> usize { self.out.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.out.is_empty() }

    /// # C: O(1) amortised
    pub fn u8(&mut self, v: u8) { self.out.push(v); }

    /// # C: O(1) amortised
    pub fn i8(&mut self, v: i8) { self.out.push(v as u8); }

    /// # C: O(1) amortised
    pub fn u16(&mut self, v: u16) { self.out.extend_from_slice(&v.to_le_bytes()); }

    /// # C: O(1) amortised
    pub fn u32(&mut self, v: u32) { self.out.extend_from_slice(&v.to_le_bytes()); }

    /// # C: O(1) amortised
    pub fn u64(&mut self, v: u64) { self.out.extend_from_slice(&v.to_le_bytes()); }

    /// # C: O(n)
    pub fn bytes(&mut self, v: &[u8]) { self.out.extend_from_slice(v); }

    /// # C: O(1)
    pub fn addr(&mut self, a: &BdAddr) { self.out.extend_from_slice(a.as_bytes()); }

    /// Write exactly `width` bytes: `v` truncated if longer, zero-padded if
    /// shorter. Every fixed-width name and key field is written this way so a
    /// short value cannot shift the fields after it. # C: O(width)
    pub fn fixed(&mut self, v: &[u8], width: usize) {
        let n = core::cmp::min(v.len(), width);
        self.out.extend_from_slice(&v[..n]);
        for _ in n..width { self.out.push(0); }
    }

    /// # C: O(1)
    pub fn finish(self) -> Vec<u8> { self.out }
}

#[cfg(test)]
#[path = "tests/codec.rs"]
mod tests;
