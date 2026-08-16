// Wire decoder: a bounds-checked cursor over one received message body.
// Every primitive is little-endian; a short buffer is `Ebadmsg`, never a panic
// and never a silently truncated value.

use crate::err::{NpError, NpResult};
use crate::uapi::limits;
use super::Qid;

/// Cursor over a received 9P message. Reads advance `off`; a read that would
/// pass `buf.len()` fails instead of wrapping or truncating.
pub struct Dec<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Dec<'a> {
    /// Wrap a full message body (the bytes AFTER `size[4] type[1] tag[2]`).
    /// # C: O(1)
    pub fn new(buf: &'a [u8]) -> Self { Self { buf, off: 0 } }

    /// Bytes not yet consumed. # C: O(1)
    pub fn remaining(&self) -> usize { self.buf.len() - self.off }

    /// Current read offset. # C: O(1)
    pub fn offset(&self) -> usize { self.off }

    /// True once every byte has been consumed. # C: O(1)
    pub fn at_end(&self) -> bool { self.off == self.buf.len() }

    fn take(&mut self, n: usize) -> NpResult<&'a [u8]> {
        let end = self.off.checked_add(n).ok_or(NpError::BadMessage)?;
        if end > self.buf.len() { return Err(NpError::BadMessage); }
        let s = &self.buf[self.off..end];
        self.off = end;
        Ok(s)
    }

    /// `b` — one byte. # C: O(1)
    pub fn u8(&mut self) -> NpResult<u8> { Ok(self.take(1)?[0]) }

    /// `w` — 16-bit little-endian. # C: O(1)
    pub fn u16(&mut self) -> NpResult<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    /// `d` — 32-bit little-endian. # C: O(1)
    pub fn u32(&mut self) -> NpResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// `q` — 64-bit little-endian. # C: O(1)
    pub fn u64(&mut self) -> NpResult<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }

    /// `s` — a 16-bit length prefix followed by that many BYTES. The protocol
    /// does not guarantee UTF-8, so the bytes are returned raw; a caller that
    /// needs `&str` uses [`Self::string`] and accepts its validity check.
    /// # C: O(1)
    pub fn bytes_str(&mut self) -> NpResult<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// `s` decoded as UTF-8. Invalid UTF-8 is `Ebadmsg` rather than a lossy
    /// substitution — a name that cannot round-trip must not reach the dcache.
    /// # C: O(len)
    pub fn string(&mut self) -> NpResult<&'a str> {
        core::str::from_utf8(self.bytes_str()?).map_err(|_| NpError::BadMessage)
    }

    /// `Q` — `type[1] version[4] path[8]`. # C: O(1)
    pub fn qid(&mut self) -> NpResult<Qid> {
        Ok(Qid { ty: self.u8()?, version: self.u32()?, path: self.u64()? })
    }

    /// `D` — `count[4] data[count]`. The count is CLAMPED to what remains
    /// rather than trusted: a server that over-declares its payload must not
    /// make the decode fail after the data it did send was already usable.
    /// # C: O(1)
    pub fn data(&mut self) -> NpResult<&'a [u8]> {
        let n = self.u32()? as usize;
        let n = n.min(self.remaining());
        self.take(n)
    }

    /// Consume the rest of the buffer verbatim. # C: O(1)
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.off..];
        self.off = self.buf.len();
        s
    }

    /// Skip `n` bytes. # C: O(1)
    pub fn skip(&mut self, n: usize) -> NpResult<()> { self.take(n).map(|_| ()) }
}

/// Parsed `size[4] type[1] tag[2]` prefix plus the body that follows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgHeader {
    /// Declared total message length INCLUDING these 7 header bytes.
    pub size: u32,
    /// Message opcode.
    pub ty: u8,
    /// Transaction tag the reply is matched by.
    pub tag: u16,
}

/// Split a received frame into its header and body. The declared `size` must
/// equal the frame length exactly: a mismatch is a framing error, and accepting
/// a short `size` would let a server hide trailing bytes from the body decoder
/// while the transport had already consumed them. # C: O(1)
pub fn split_header(frame: &[u8]) -> NpResult<(MsgHeader, &[u8])> {
    if frame.len() < limits::HDRSZ { return Err(NpError::BadMessage); }
    let size = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let hdr = MsgHeader { size, ty: frame[4], tag: u16::from_le_bytes([frame[5], frame[6]]) };
    if size as usize != frame.len() { return Err(NpError::BadMessage); }
    Ok((hdr, &frame[limits::HDRSZ..]))
}

/// Read the declared message length from the first 4 bytes of a stream, used by
/// a byte-stream transport to learn how much more to read. `None` until 4 bytes
/// are buffered. # C: O(1)
pub fn peek_size(head: &[u8]) -> Option<u32> {
    if head.len() < 4 { return None; }
    Some(u32::from_le_bytes([head[0], head[1], head[2], head[3]]))
}
