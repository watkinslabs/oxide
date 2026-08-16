//! Little-endian read and write primitives, the basic L2CAP header, and the
//! signalling command header.
//!
//! Every decoder here refuses a truncated or over-long buffer rather than
//! parsing what is present: a length field that disagrees with the bytes
//! delivered is a malformed PDU, not a short one.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::l2cap as u;

/// Cursor over a received buffer. Each read either consumes exactly its width
/// or leaves the cursor untouched and reports `None`.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A cursor at the start of `buf`. # C: O(1)
    pub fn new(buf: &'a [u8]) -> Reader<'a> { Reader { buf, pos: 0 } }

    /// Bytes not yet consumed. # C: O(1)
    pub fn remaining(&self) -> usize { self.buf.len() - self.pos }

    /// Whether every byte has been consumed. # C: O(1)
    pub fn is_empty(&self) -> bool { self.remaining() == 0 }

    /// Offset of the cursor from the start of the buffer. # C: O(1)
    pub fn pos(&self) -> usize { self.pos }

    /// Next byte. # C: O(1)
    pub fn u8(&mut self) -> Option<u8> {
        if self.remaining() < 1 { return None; }
        let v = self.buf[self.pos];
        self.pos += 1;
        Some(v)
    }

    /// Next little-endian 16-bit word. # C: O(1)
    pub fn le16(&mut self) -> Option<u16> {
        if self.remaining() < 2 { return None; }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    /// Next little-endian 32-bit word. # C: O(1)
    pub fn le32(&mut self) -> Option<u32> {
        if self.remaining() < 4 { return None; }
        let b = &self.buf[self.pos..self.pos + 4];
        self.pos += 4;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Next `n` bytes as a borrowed slice. # C: O(1)
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n { return None; }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    /// Everything left, consuming it. # C: O(1)
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

/// Append-only little-endian writer.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// An empty buffer. # C: O(1)
    pub fn new() -> Writer { Writer { out: Vec::new() } }

    /// Bytes written so far. # C: O(1)
    pub fn len(&self) -> usize { self.out.len() }

    /// Whether nothing has been written. # C: O(1)
    pub fn is_empty(&self) -> bool { self.out.is_empty() }

    /// Append one byte. # C: O(1) amortised
    pub fn u8(&mut self, v: u8) { self.out.push(v); }

    /// Append a little-endian 16-bit word. # C: O(1) amortised
    pub fn le16(&mut self, v: u16) { self.out.extend_from_slice(&v.to_le_bytes()); }

    /// Append a little-endian 32-bit word. # C: O(1) amortised
    pub fn le32(&mut self, v: u32) { self.out.extend_from_slice(&v.to_le_bytes()); }

    /// Append raw bytes. # C: O(n)
    pub fn bytes(&mut self, v: &[u8]) { self.out.extend_from_slice(v); }

    /// The written buffer. # C: O(1)
    pub fn into_vec(self) -> Vec<u8> { self.out }

    /// The written buffer, borrowed. # C: O(1)
    pub fn as_slice(&self) -> &[u8] { &self.out }
}

/// Basic L2CAP header: payload length then channel identifier.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Hdr {
    pub len: u16,
    pub cid: u16,
}

impl Hdr {
    /// Read a header off the front of `buf`. # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<Hdr> {
        if buf.len() < u::HDR_SIZE { return None; }
        Some(Hdr { len: u16::from_le_bytes([buf[0], buf[1]]), cid: u16::from_le_bytes([buf[2], buf[3]]) })
    }

    /// Write the header. # C: O(1)
    pub fn encode(&self, w: &mut Writer) { w.le16(self.len); w.le16(self.cid); }
}

/// A whole basic-header frame split into its channel and its payload. The
/// declared length must equal the bytes present: a frame carrying fewer is
/// truncated and one carrying more has a second frame glued to it, and both are
/// refused rather than guessed at. # C: O(1)
pub fn decode_frame(buf: &[u8]) -> Option<(u16, &[u8])> {
    let h = Hdr::decode(buf)?;
    let body = &buf[u::HDR_SIZE..];
    if body.len() != h.len as usize { return None; }
    Some((h.cid, body))
}

/// Frame a payload for `cid`. # C: O(n)
pub fn encode_frame(cid: u16, body: &[u8]) -> Option<Vec<u8>> {
    if body.len() > u16::MAX as usize { return None; }
    let mut w = Writer::new();
    Hdr { len: body.len() as u16, cid }.encode(&mut w);
    w.bytes(body);
    Some(w.into_vec())
}

/// Signalling command header: code, identifier, payload length.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CmdHdr {
    pub code: u8,
    pub ident: u8,
    pub len: u16,
}

impl CmdHdr {
    /// Read a command header off the front of `buf`. # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<CmdHdr> {
        if buf.len() < u::CMD_HDR_SIZE { return None; }
        Some(CmdHdr { code: buf[0], ident: buf[1], len: u16::from_le_bytes([buf[2], buf[3]]) })
    }

    /// Write the header. # C: O(1)
    pub fn encode(&self, w: &mut Writer) { w.u8(self.code); w.u8(self.ident); w.le16(self.len); }
}

/// One command carved out of a signalling packet: its header and exactly the
/// payload the header declared, plus the offset the next command starts at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SplitCmd<'a> {
    pub hdr: CmdHdr,
    pub body: &'a [u8],
    pub next: usize,
}

/// Split the first command out of a signalling packet. A declared length past
/// the end of the packet is malformed; a zero identifier is malformed, which is
/// what stops a peer from correlating a response to no request. # C: O(1)
pub fn split_cmd(buf: &[u8]) -> Option<SplitCmd<'_>> {
    let hdr = CmdHdr::decode(buf)?;
    if hdr.ident == 0 { return None; }
    let start = u::CMD_HDR_SIZE;
    let end = start.checked_add(hdr.len as usize)?;
    if end > buf.len() { return None; }
    Some(SplitCmd { hdr, body: &buf[start..end], next: end })
}

/// Frame one signalling command. # C: O(n)
pub fn encode_cmd(code: u8, ident: u8, body: &[u8]) -> Option<Vec<u8>> {
    if body.len() > u16::MAX as usize { return None; }
    let mut w = Writer::new();
    CmdHdr { code, ident, len: body.len() as u16 }.encode(&mut w);
    w.bytes(body);
    Some(w.into_vec())
}

#[cfg(test)]
#[path = "tests/codec.rs"]
mod tests;
