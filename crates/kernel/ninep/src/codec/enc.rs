// Wire encoder: builds one outgoing message, header first, with the `size[4]`
// field back-patched once the body is complete.

extern crate alloc;
use alloc::vec::Vec;

use crate::err::{NpError, NpResult};
use crate::uapi::limits;
use super::Qid;

/// Builder for one outgoing 9P message. Construct with [`Enc::request`], append
/// the body, then [`Enc::finish`] to back-patch `size` and yield the frame.
pub struct Enc {
    buf: Vec<u8>,
    /// Largest frame the negotiated `msize` permits; an append past it fails
    /// rather than producing a message the server will reject or truncate.
    msize: usize,
}

impl Enc {
    /// Start a message with `size[4] type[1] tag[2]`; `size` is a placeholder
    /// until [`Self::finish`]. # C: O(1)
    pub fn request(ty: u8, tag: u16, msize: u32) -> Self {
        let mut buf = Vec::with_capacity(limits::HDRSZ);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(ty);
        buf.extend_from_slice(&tag.to_le_bytes());
        Self { buf, msize: msize as usize }
    }

    /// Bytes written so far, header included. # C: O(1)
    pub fn len(&self) -> usize { self.buf.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }

    /// Room left before the negotiated `msize` is reached. # C: O(1)
    pub fn headroom(&self) -> usize { self.msize.saturating_sub(self.buf.len()) }

    fn push(&mut self, b: &[u8]) -> NpResult<()> {
        if self.buf.len() + b.len() > self.msize { return Err(NpError::MsgTooLarge); }
        self.buf.extend_from_slice(b);
        Ok(())
    }

    /// `b` # C: O(1)
    pub fn u8(&mut self, v: u8) -> NpResult<()> { self.push(&[v]) }
    /// `w` # C: O(1)
    pub fn u16(&mut self, v: u16) -> NpResult<()> { self.push(&v.to_le_bytes()) }
    /// `d` # C: O(1)
    pub fn u32(&mut self, v: u32) -> NpResult<()> { self.push(&v.to_le_bytes()) }
    /// `q` # C: O(1)
    pub fn u64(&mut self, v: u64) -> NpResult<()> { self.push(&v.to_le_bytes()) }

    /// `s` — 16-bit byte count then the bytes. A name longer than `u16::MAX` is
    /// unrepresentable on the wire and is refused. # C: O(len)
    pub fn bytes_str(&mut self, s: &[u8]) -> NpResult<()> {
        if s.len() > u16::MAX as usize { return Err(NpError::NameTooLong); }
        self.u16(s.len() as u16)?;
        self.push(s)
    }

    /// `s` from a `&str`. # C: O(len)
    pub fn string(&mut self, s: &str) -> NpResult<()> { self.bytes_str(s.as_bytes()) }

    /// `Q` # C: O(1)
    pub fn qid(&mut self, q: &Qid) -> NpResult<()> {
        self.u8(q.ty)?; self.u32(q.version)?; self.u64(q.path)
    }

    /// `D` — 32-bit byte count then the payload (the `Twrite` body shape).
    /// # C: O(len)
    pub fn data(&mut self, d: &[u8]) -> NpResult<()> {
        self.u32(d.len() as u32)?;
        self.push(d)
    }

    /// Raw append with no length prefix, for a payload already counted by a
    /// separately-written field. # C: O(len)
    pub fn raw(&mut self, d: &[u8]) -> NpResult<()> { self.push(d) }

    /// Back-patch `size[4]` and yield the finished frame. # C: O(1)
    pub fn finish(mut self) -> NpResult<Vec<u8>> {
        let n = self.buf.len();
        if n > self.msize { return Err(NpError::MsgTooLarge); }
        if n > u32::MAX as usize { return Err(NpError::MsgTooLarge); }
        self.buf[..4].copy_from_slice(&(n as u32).to_le_bytes());
        Ok(self.buf)
    }
}
