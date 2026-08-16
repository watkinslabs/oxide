// The XDR decoder.
//
// Every read is bounds-checked and every variable-length read consumes its
// padding. A decoder that skipped padding would leave the cursor one to three
// bytes short of the next item, and each following field would then be read
// from a shifted offset — a file size assembled from half of one word and half
// of the next is a plausible number, not a detectable fault.

use crate::err::{RpcError, RpcResult};
use super::pad_of;

/// A cursor over an encoded XDR body.
#[derive(Clone, Debug)]
pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    /// # C: O(1)
    pub fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    /// Bytes consumed so far. # C: O(1)
    pub fn pos(&self) -> usize { self.pos }

    /// Bytes not yet consumed. # C: O(1)
    pub fn remaining(&self) -> usize { self.buf.len() - self.pos }

    /// True when the whole body has been consumed. # C: O(1)
    pub fn at_end(&self) -> bool { self.pos == self.buf.len() }

    /// The bytes not yet consumed, without consuming them. # C: O(1)
    pub fn rest(&self) -> &'a [u8] { &self.buf[self.pos..] }

    fn take(&mut self, n: usize) -> RpcResult<&'a [u8]> {
        if self.remaining() < n { return Err(RpcError::Unparsable); }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// A 32-bit unsigned integer. # C: O(1)
    pub fn u32(&mut self) -> RpcResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A 32-bit signed integer. # C: O(1)
    pub fn i32(&mut self) -> RpcResult<i32> { Ok(self.u32()? as i32) }

    /// A 64-bit unsigned integer (XDR hyper). # C: O(1)
    pub fn u64(&mut self) -> RpcResult<u64> {
        let b = self.take(8)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(b);
        Ok(u64::from_be_bytes(v))
    }

    /// A boolean.
    ///
    /// A word that is neither 0 nor 1 is a protocol fault, not "true": XDR
    /// defines the type as exactly those two values, and treating anything
    /// non-zero as set would accept a misaligned decode as a valid discriminant
    /// and then read an optional field that is not there.
    /// # C: O(1)
    pub fn bool(&mut self) -> RpcResult<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RpcError::Unparsable),
        }
    }

    /// Fixed-length opaque of exactly `len` bytes, plus its padding. # C: O(len)
    pub fn opaque_fixed(&mut self, len: usize) -> RpcResult<&'a [u8]> {
        let b = self.take(len)?;
        let pad = pad_of(len);
        if pad != 0 { self.take(pad)?; }
        Ok(b)
    }

    /// Variable-length opaque, refusing any length above `max`.
    ///
    /// The cap is mandatory rather than advisory: a length word is attacker- or
    /// fault-supplied, and a decoder that trusts it either allocates whatever
    /// the wire says or reads past the buffer. # C: O(len)
    pub fn opaque(&mut self, max: usize) -> RpcResult<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max { return Err(RpcError::Unparsable); }
        self.opaque_fixed(len)
    }

    /// A string, bounded like a variable-length opaque and required to be
    /// valid UTF-8. # C: O(len)
    pub fn string(&mut self, max: usize) -> RpcResult<&'a str> {
        let b = self.opaque(max)?;
        core::str::from_utf8(b).map_err(|_| RpcError::Unparsable)
    }

    /// Skip `n` bytes without interpreting them. # C: O(1)
    pub fn skip(&mut self, n: usize) -> RpcResult<()> { self.take(n).map(|_| ()) }

    /// Skip `n` XDR words. # C: O(1)
    pub fn skip_words(&mut self, n: usize) -> RpcResult<()> { self.skip(n * 4) }
}
