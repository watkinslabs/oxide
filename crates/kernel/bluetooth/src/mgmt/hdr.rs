//! The six-byte frame header shared by commands and events, and the two reply
//! shapes every command produces.
//!
//! An event's header opcode field carries the EVENT code; the command opcode it
//! answers, when there is one, is the first field of the payload. A frame whose
//! header length disagrees with the bytes that follow is malformed and draws no
//! reply at all — the distinction is the caller's, made in `mgmt::validate`.

use alloc::vec::Vec;

use super::codec::{Reader, Writer};
use crate::uapi::mgmt::ev::{MGMT_EV_CMD_COMPLETE, MGMT_EV_CMD_STATUS};
use crate::uapi::mgmt::limits::MGMT_HDR_SIZE;

/// Frame header: which command or event, which controller, how many bytes follow.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MgmtHdr {
    pub opcode: u16,
    pub index: u16,
    pub len: u16,
}

impl MgmtHdr {
    /// # C: O(1)
    pub fn new(opcode: u16, index: u16, len: u16) -> MgmtHdr { MgmtHdr { opcode, index, len } }

    /// Read a header off the front of a frame. `None` when fewer than six bytes
    /// are present; the caller drops such a frame without replying because it
    /// cannot know which command to blame. # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<MgmtHdr> {
        let mut r = Reader::new(buf);
        Some(MgmtHdr { opcode: r.u16()?, index: r.u16()?, len: r.u16()? })
    }

    /// # C: O(1)
    pub fn encode_into(&self, w: &mut Writer) {
        w.u16(self.opcode);
        w.u16(self.index);
        w.u16(self.len);
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_HDR_SIZE);
        self.encode_into(&mut w);
        w.finish()
    }
}

/// A whole framed message: header plus payload. # C: O(n)
pub fn frame(opcode: u16, index: u16, payload: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(MGMT_HDR_SIZE + payload.len());
    MgmtHdr::new(opcode, index, payload.len() as u16).encode_into(&mut w);
    w.bytes(payload);
    w.finish()
}

/// Split a frame into its header and the payload the header declares. `None`
/// when the frame is shorter than a header or the declared length disagrees
/// with the bytes present — both are drop-without-reply conditions. # C: O(1)
pub fn split(buf: &[u8]) -> Option<(MgmtHdr, &[u8])> {
    let hdr = MgmtHdr::decode(buf)?;
    let body = &buf[MGMT_HDR_SIZE..];
    if body.len() != hdr.len as usize { return None; }
    Some((hdr, body))
}

/// Command complete: the command succeeded, or failed in a way that carries a
/// return payload. # C: O(n)
pub fn cmd_complete(index: u16, opcode: u16, status: u8, data: &[u8]) -> Vec<u8> {
    let mut p = Writer::with_capacity(3 + data.len());
    p.u16(opcode);
    p.u8(status);
    p.bytes(data);
    frame(MGMT_EV_CMD_COMPLETE, index, &p.finish())
}

/// Command status: the command was refused before it ran, or was accepted and
/// will complete later. Carries no payload beyond the opcode and status. # C: O(1)
pub fn cmd_status(index: u16, opcode: u16, status: u8) -> Vec<u8> {
    let mut p = Writer::with_capacity(3);
    p.u16(opcode);
    p.u8(status);
    frame(MGMT_EV_CMD_STATUS, index, &p.finish())
}

/// Payload of a command complete: the opcode answered, the status, the rest. # C: O(1)
pub fn parse_cmd_complete(payload: &[u8]) -> Option<(u16, u8, &[u8])> {
    let mut r = Reader::new(payload);
    let opcode = r.u16()?;
    let status = r.u8()?;
    Some((opcode, status, r.rest()))
}

/// Payload of a command status. Exactly three bytes; a longer one is malformed. # C: O(1)
pub fn parse_cmd_status(payload: &[u8]) -> Option<(u16, u8)> {
    let mut r = Reader::new(payload);
    let opcode = r.u16()?;
    let status = r.u8()?;
    if !r.done() { return None; }
    Some((opcode, status))
}

#[cfg(test)]
#[path = "tests/hdr.rs"]
mod tests;
