//! H:4 framing: the packet-type prefix, the four headers, and the streaming
//! reassembler a byte-oriented transport feeds.
//!
//! A packet-oriented transport hands whole frames to `parse_frame`. A byte
//! stream hands bytes to `H4Decoder`, which is the same decision expressed as a
//! state machine so a frame split across reads still parses exactly once.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::hci::{
    HCI_ACLDATA_PKT, HCI_ACL_HDR_SIZE, HCI_COMMAND_HDR_SIZE, HCI_COMMAND_PKT,
    HCI_EVENT_HDR_SIZE, HCI_EVENT_PKT, HCI_ISODATA_PKT, HCI_ISO_HDR_SIZE,
    HCI_MAX_FRAME_SIZE, HCI_SCODATA_PKT, HCI_SCO_HDR_SIZE,
};

/// One decoded HCI frame: its packet type and the payload that follows the
/// header, with the header fields already read out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub pkt_type: u8,
    /// Header word: the opcode for a command, the handle+flags word for ACL and
    /// SCO and ISO, and the event code for an event.
    pub head: u16,
    /// Payload following the header, of exactly the length the header declared.
    pub body: Vec<u8>,
}

/// Header width for a packet type, or `None` when the type is not one of the
/// five framed types. # C: O(1)
pub fn header_len(pkt_type: u8) -> Option<usize> {
    match pkt_type {
        HCI_COMMAND_PKT => Some(HCI_COMMAND_HDR_SIZE),
        HCI_ACLDATA_PKT => Some(HCI_ACL_HDR_SIZE),
        HCI_SCODATA_PKT => Some(HCI_SCO_HDR_SIZE),
        HCI_EVENT_PKT   => Some(HCI_EVENT_HDR_SIZE),
        HCI_ISODATA_PKT => Some(HCI_ISO_HDR_SIZE),
        _ => None,
    }
}

/// Body length a complete header declares. Command and event headers carry a
/// single-byte length; ACL and ISO carry a little-endian 16-bit one; SCO carries
/// one byte after its handle word. # C: O(1)
pub fn body_len(pkt_type: u8, hdr: &[u8]) -> Option<usize> {
    let need = header_len(pkt_type)?;
    if hdr.len() < need { return None; }
    Some(match pkt_type {
        HCI_COMMAND_PKT => hdr[2] as usize,
        HCI_EVENT_PKT   => hdr[1] as usize,
        HCI_SCODATA_PKT => hdr[2] as usize,
        HCI_ACLDATA_PKT | HCI_ISODATA_PKT => u16::from_le_bytes([hdr[2], hdr[3]]) as usize,
        _ => return None,
    })
}

/// Header word a complete header carries: the little-endian opcode or
/// handle-and-flags word, or the event code widened from its single byte.
/// # C: O(1)
pub fn header_word(pkt_type: u8, hdr: &[u8]) -> Option<u16> {
    let need = header_len(pkt_type)?;
    if hdr.len() < need { return None; }
    Some(match pkt_type {
        HCI_EVENT_PKT => hdr[0] as u16,
        _ => u16::from_le_bytes([hdr[0], hdr[1]]),
    })
}

/// Parse one whole H:4 frame, prefix byte included. A frame whose declared body
/// length disagrees with the bytes present is rejected rather than truncated —
/// a short read that parsed as a valid short frame would hand the event
/// dispatcher a payload the controller never sent. # C: O(len)
pub fn parse_frame(bytes: &[u8]) -> Option<Frame> {
    let (&pkt_type, rest) = bytes.split_first()?;
    let hlen = header_len(pkt_type)?;
    if rest.len() < hlen { return None; }
    let (hdr, body) = rest.split_at(hlen);
    let blen = body_len(pkt_type, hdr)?;
    if body.len() != blen { return None; }
    Some(Frame { pkt_type, head: header_word(pkt_type, hdr)?, body: body.to_vec() })
}

/// Build one whole H:4 frame from a packet type, its header word and its body.
/// The declared length is derived from the body, so an encode can never claim a
/// length the frame does not carry. # C: O(len)
pub fn build_frame(pkt_type: u8, head: u16, body: &[u8]) -> Option<Vec<u8>> {
    let hlen = header_len(pkt_type)?;
    let mut out = Vec::with_capacity(1 + hlen + body.len());
    out.push(pkt_type);
    match pkt_type {
        HCI_EVENT_PKT => {
            if body.len() > u8::MAX as usize { return None; }
            out.push(head as u8);
            out.push(body.len() as u8);
        }
        HCI_COMMAND_PKT | HCI_SCODATA_PKT => {
            if body.len() > u8::MAX as usize { return None; }
            out.extend_from_slice(&head.to_le_bytes());
            out.push(body.len() as u8);
        }
        HCI_ACLDATA_PKT | HCI_ISODATA_PKT => {
            if body.len() > u16::MAX as usize { return None; }
            out.extend_from_slice(&head.to_le_bytes());
            out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        }
        _ => return None,
    }
    out.extend_from_slice(body);
    Some(out)
}

/// What the decoder is waiting for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Want { Type, Header, Body }

/// Streaming H:4 decoder for a byte-oriented transport.
///
/// An unknown packet-type byte desynchronises the stream irrecoverably — there
/// is no framing to resynchronise against — so the decoder latches an error
/// rather than guessing a boundary and handing up frames assembled from the
/// middle of a real one.
pub struct H4Decoder {
    want: Want,
    pkt_type: u8,
    hlen: usize,
    blen: usize,
    buf: Vec<u8>,
    desynced: bool,
}

impl Default for H4Decoder {
    fn default() -> Self { Self::new() }
}

impl H4Decoder {
    /// A decoder waiting for the first packet-type byte. # C: O(1)
    pub fn new() -> H4Decoder {
        H4Decoder { want: Want::Type, pkt_type: 0, hlen: 0, blen: 0, buf: Vec::new(), desynced: false }
    }

    /// Whether the stream has desynchronised. A desynced decoder yields no
    /// further frames until it is reset. # C: O(1)
    pub fn desynced(&self) -> bool { self.desynced }

    /// Drop all partial state and wait for a packet-type byte again. Used when
    /// the transport itself resynchronises, such as a controller reopen.
    /// # C: O(1)
    pub fn reset(&mut self) {
        self.want = Want::Type; self.buf.clear();
        self.pkt_type = 0; self.hlen = 0; self.blen = 0; self.desynced = false;
    }

    /// Feed bytes, returning every complete frame they finished. # C: O(n)
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        for &b in bytes {
            if self.desynced { break; }
            if let Some(f) = self.push(b) { out.push(f); }
        }
        out
    }

    fn push(&mut self, b: u8) -> Option<Frame> {
        match self.want {
            Want::Type => {
                match header_len(b) {
                    Some(h) => { self.pkt_type = b; self.hlen = h; self.want = Want::Header; }
                    None => self.desynced = true,
                }
                None
            }
            Want::Header => {
                self.buf.push(b);
                if self.buf.len() < self.hlen { return None; }
                self.blen = body_len(self.pkt_type, &self.buf)?;
                // A declared body larger than any frame the transport can carry
                // is a corrupt header, not a big packet: accepting it would park
                // the decoder forever waiting for bytes that never come.
                if self.blen > HCI_MAX_FRAME_SIZE { self.desynced = true; return None; }
                if self.blen == 0 { return Some(self.finish()); }
                self.want = Want::Body;
                None
            }
            Want::Body => {
                self.buf.push(b);
                if self.buf.len() < self.hlen + self.blen { return None; }
                Some(self.finish())
            }
        }
    }

    fn finish(&mut self) -> Frame {
        let head = header_word(self.pkt_type, &self.buf).unwrap_or(0);
        let body = self.buf[self.hlen..].to_vec();
        let pkt_type = self.pkt_type;
        self.want = Want::Type; self.buf.clear(); self.hlen = 0; self.blen = 0;
        Frame { pkt_type, head, body }
    }
}

#[cfg(test)]
#[path = "tests/packet.rs"]
mod tests;
