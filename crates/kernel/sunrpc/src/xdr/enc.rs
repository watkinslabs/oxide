// The XDR encoder.

extern crate alloc;
use alloc::vec::Vec;

use crate::err::{RpcError, RpcResult};
use super::pad_of;

/// Appends XDR items to a growing buffer.
///
/// The buffer is the encoded body ONLY: no fragment header and no call header
/// are implied, so the same encoder serves an argument body, a credential body
/// measured before it is spliced in, and a test fixture.
pub struct Enc {
    buf: Vec<u8>,
    limit: usize,
}

impl Enc {
    /// An encoder that refuses to grow past `limit` bytes. # C: O(1)
    pub fn with_limit(limit: usize) -> Self { Self { buf: Vec::new(), limit } }

    /// An encoder bounded only by the protocol's fragment maximum. # C: O(1)
    pub fn new() -> Self { Self::with_limit(crate::uapi::frag::MAX_FRAGMENT_SIZE as usize) }

    /// Bytes written so far. # C: O(1)
    pub fn len(&self) -> usize { self.buf.len() }

    /// True when nothing has been written. # C: O(1)
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }

    /// The encoded bytes. # C: O(1)
    pub fn as_slice(&self) -> &[u8] { &self.buf }

    /// Consume the encoder for its bytes. # C: O(1)
    pub fn finish(self) -> Vec<u8> { self.buf }

    fn room(&self, n: usize) -> RpcResult<()> {
        if self.buf.len() + n > self.limit { return Err(RpcError::MsgTooLarge); }
        Ok(())
    }

    /// A 32-bit unsigned integer. # C: O(1)
    pub fn u32(&mut self, v: u32) -> RpcResult<()> {
        self.room(4)?;
        self.buf.extend_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// A 32-bit signed integer. # C: O(1)
    pub fn i32(&mut self, v: i32) -> RpcResult<()> { self.u32(v as u32) }

    /// A 64-bit unsigned integer — XDR calls it a hyper and encodes it as two
    /// big-endian words, high word first. # C: O(1)
    pub fn u64(&mut self, v: u64) -> RpcResult<()> {
        self.room(8)?;
        self.buf.extend_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// A boolean, which XDR encodes as an `i32` of exactly 0 or 1. # C: O(1)
    pub fn bool(&mut self, v: bool) -> RpcResult<()> { self.u32(u32::from(v)) }

    /// Fixed-length opaque: the bytes, then padding, with NO length prefix.
    /// # C: O(len)
    pub fn opaque_fixed(&mut self, b: &[u8]) -> RpcResult<()> {
        let pad = pad_of(b.len());
        self.room(b.len() + pad)?;
        self.buf.extend_from_slice(b);
        self.buf.extend(core::iter::repeat(0u8).take(pad));
        Ok(())
    }

    /// Variable-length opaque: a length word, the bytes, then padding.
    /// # C: O(len)
    pub fn opaque(&mut self, b: &[u8]) -> RpcResult<()> {
        if b.len() > u32::MAX as usize { return Err(RpcError::MsgTooLarge); }
        self.u32(b.len() as u32)?;
        self.opaque_fixed(b)
    }

    /// A string, encoded exactly as a variable-length opaque. # C: O(len)
    pub fn string(&mut self, s: &str) -> RpcResult<()> { self.opaque(s.as_bytes()) }

    /// Splice already-encoded bytes in verbatim, without a length prefix or
    /// padding. Used to place a credential body whose length had to be known
    /// before it could be written. # C: O(len)
    pub fn raw(&mut self, b: &[u8]) -> RpcResult<()> {
        self.room(b.len())?;
        self.buf.extend_from_slice(b);
        Ok(())
    }

    /// Overwrite the word at `off` with `v`.
    ///
    /// A length that is only known after its contents are encoded is reserved
    /// as a zero word and patched here, rather than encoded into a scratch
    /// buffer and copied — the copy is what the fixed-size variants exist to
    /// avoid. # C: O(1)
    pub fn patch_u32(&mut self, off: usize, v: u32) -> RpcResult<()> {
        if off + 4 > self.buf.len() { return Err(RpcError::Unparsable); }
        self.buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
        Ok(())
    }

    /// Reserve a word to be patched later and return its offset. # C: O(1)
    pub fn reserve_u32(&mut self) -> RpcResult<usize> {
        let at = self.buf.len();
        self.u32(0)?;
        Ok(at)
    }
}

impl Default for Enc {
    fn default() -> Self { Self::new() }
}
