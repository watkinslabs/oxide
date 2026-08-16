//! Frame encode and decode.
//!
//! A frame is an address byte, a control byte, a one- or two-byte length, the
//! payload, and a check byte. The length field's extended-address bit says
//! which width it has, so the header width is only known after reading it.

use alloc::vec::Vec;

use crate::uapi::rfcomm as u;
use super::fcs;

/// Shortest possible frame: address, control, one-byte length, check byte.
pub const FRAME_MIN_LEN: usize = 4;

/// A decoded frame. The payload is what remains after the header and before the
/// check byte; `declared_len` is what the length field claimed, which a caller
/// may compare against the payload it actually got.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub addr: u8,
    pub ctrl: u8,
    pub declared_len: usize,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// The DLCI the frame addresses. # C: O(1)
    pub fn dlci(&self) -> u8 { u::get_dlci(self.addr) }

    /// The command/response bit of the address byte. # C: O(1)
    pub fn cr(&self) -> bool { u::test_cr(self.addr) }

    /// The frame type, with the poll/final bit masked out. # C: O(1)
    pub fn ftype(&self) -> u8 { u::get_type(self.ctrl) }

    /// The poll/final bit, which on a UIH data frame means a credit byte leads
    /// the payload. # C: O(1)
    pub fn pf(&self) -> bool { u::test_pf(self.ctrl) }

    /// Whether the frame carries user data or a multiplexer command rather than
    /// a link-control command. # C: O(1)
    pub fn is_uih(&self) -> bool { self.ftype() == u::RFCOMM_UIH }
}

/// Why a frame could not be decoded.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Fewer bytes than the shortest frame, or a two-byte length field whose
    /// second byte is past the end.
    Truncated,
    /// The check byte does not match the header.
    BadFcs,
}

/// Decode one frame out of a complete link-layer packet. The check byte is
/// verified here, with the coverage the frame type demands, so a caller never
/// sees a frame whose header was corrupted. # C: O(1)
pub fn decode(buf: &[u8]) -> Result<Frame<'_>, FrameError> {
    if buf.len() < FRAME_MIN_LEN { return Err(FrameError::Truncated); }
    let addr = buf[0];
    let ctrl = buf[1];
    let (hdr, declared_len) = if u::test_ea(buf[2]) {
        (3usize, u::get_len8(buf[2]))
    } else {
        if buf.len() < FRAME_MIN_LEN + 1 { return Err(FrameError::Truncated); }
        (4usize, u::get_len16(buf[2], buf[3]))
    };
    if buf.len() < hdr + 1 { return Err(FrameError::Truncated); }
    let fcs = buf[buf.len() - 1];
    let is_uih = u::get_type(ctrl) == u::RFCOMM_UIH;
    if !fcs::check(addr, ctrl, buf[2], is_uih, fcs) { return Err(FrameError::BadFcs); }
    Ok(Frame { addr, ctrl, declared_len, payload: &buf[hdr..buf.len() - 1] })
}

/// Encode a link-control frame — one with no payload and a poll/final bit set.
/// Its check byte covers the length byte as well as the header. # C: O(1)
pub fn encode_cmd(addr: u8, ftype: u8, pf: bool) -> Vec<u8> {
    let ctrl = u::ctrl(ftype, pf);
    let len = u::len8(0);
    let mut v = Vec::with_capacity(FRAME_MIN_LEN);
    v.push(addr);
    v.push(ctrl);
    v.push(len);
    v.push(fcs::fcs_cmd(addr, ctrl, len));
    v
}

/// Encode a UIH frame carrying `payload`. The length field widens to two bytes
/// past what one byte can express, and the check byte covers the header only.
/// # C: O(n) in payload length
pub fn encode_uih(addr: u8, pf: bool, payload: &[u8]) -> Vec<u8> {
    let ctrl = u::ctrl(u::RFCOMM_UIH, pf);
    let mut v = Vec::with_capacity(payload.len() + FRAME_MIN_LEN + 1);
    v.push(addr);
    v.push(ctrl);
    if payload.len() > u::RFCOMM_LEN8_MAX {
        v.push(u::len16_lo(payload.len()));
        v.push(u::len16_hi(payload.len()));
    } else {
        v.push(u::len8(payload.len()));
    }
    v.extend_from_slice(payload);
    v.push(fcs::fcs_uih(addr, ctrl));
    v
}
