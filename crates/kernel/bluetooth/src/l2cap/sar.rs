//! Segmentation and reassembly: cutting an SDU into PDUs that fit one packet,
//! and putting the pieces back together on receipt.
//!
//! The first piece of a segmented SDU carries the total length, so a receiver
//! knows when it has the whole thing and can refuse one that grows past what it
//! agreed to accept.

extern crate alloc;
use alloc::vec::Vec;

use super::chan::Channel;
use super::ctrl::ertm_hdr_size;
use crate::uapi::l2cap as u;

/// One PDU of a segmented SDU: its segmentation state, the total SDU length
/// when this is the first piece, and the payload bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment {
    pub sar: u8,
    /// Total SDU length, carried only by the first piece.
    pub sdu_len: Option<u16>,
    pub payload: Vec<u8>,
}

impl Segment {
    /// The bytes this segment puts on the wire after the control field: the
    /// length prefix when present, then the payload. # C: O(n)
    pub fn wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(u::SDULEN_SIZE + self.payload.len());
        if let Some(l) = self.sdu_len { v.extend_from_slice(&l.to_le_bytes()); }
        v.extend_from_slice(&self.payload);
        v
    }
}

/// Payload each PDU of a sequence-numbered channel may carry. One PDU must fit
/// one packet, so the link's packet size, the baseband payload ceiling, the
/// framing overhead and the peer's declared PDU size all bound it. A bound that
/// leaves no room is not a small PDU, it is an unusable channel. # C: O(1)
pub fn ertm_pdu_len(link_mtu: u16, fcs: u8, ext_ctrl: bool, remote_mps: u16) -> Option<usize> {
    let mut n = core::cmp::min(link_mtu, u::BREDR_MAX_PAYLOAD) as usize;
    if fcs == u::FCS_CRC16 { n = n.checked_sub(u::FCS_SIZE)?; }
    n = n.checked_sub(ertm_hdr_size(ext_ctrl))?;
    n = core::cmp::min(n, remote_mps as usize);
    if n == 0 { return None; }
    Some(n)
}

/// Cut an SDU into segments of at most `pdu_len` payload bytes each. An SDU
/// that fits one PDU is sent unsegmented and carries no length prefix; anything
/// longer is a start, zero or more continuations, and an end. # C: O(n)
pub fn segment_sdu(sdu: &[u8], pdu_len: usize) -> Option<Vec<Segment>> {
    if pdu_len == 0 { return None; }
    if sdu.len() > u::DEFAULT_MAX_SDU_SIZE as usize { return None; }
    let mut out = Vec::new();
    if sdu.len() <= pdu_len {
        out.push(Segment { sar: u::SAR_UNSEGMENTED, sdu_len: None, payload: sdu.to_vec() });
        return Some(out);
    }
    let total = sdu.len() as u16;
    let mut off = 0usize;
    let mut first = true;
    while off < sdu.len() {
        let take = core::cmp::min(pdu_len, sdu.len() - off);
        let last = off + take == sdu.len();
        let sar = if first { u::SAR_START } else if last { u::SAR_END } else { u::SAR_CONTINUE };
        out.push(Segment {
            sar,
            sdu_len: if first { Some(total) } else { None },
            payload: sdu[off..off + take].to_vec(),
        });
        off += take;
        first = false;
    }
    Some(out)
}

/// What a received segment did to the reassembly in progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reassembly {
    /// More pieces are needed.
    Incomplete,
    /// The SDU is whole.
    Complete(Vec<u8>),
    /// The sequence was not one that can produce an SDU — a continuation with
    /// no start, a start on top of one already in progress, a total that
    /// exceeds what this end agreed to accept, or a length that disagrees with
    /// the bytes delivered. The partial SDU is discarded.
    Error,
}

/// Feed one segment into the channel's reassembly buffer. # C: O(n)
pub fn reassemble(chan: &mut Channel, sar: u8, data: &[u8]) -> Reassembly {
    let r = reassemble_inner(chan, sar, data);
    if r == Reassembly::Error { chan.ertm.sdu.clear(); chan.ertm.sdu_len = 0; }
    if let Reassembly::Complete(_) = r { chan.ertm.sdu = Vec::new(); chan.ertm.sdu_len = 0; }
    r
}

/// The reassembly decision itself, without the discard the caller applies on
/// error. # C: O(n)
fn reassemble_inner(chan: &mut Channel, sar: u8, data: &[u8]) -> Reassembly {
    match sar {
        u::SAR_UNSEGMENTED => {
            if !chan.ertm.sdu.is_empty() { return Reassembly::Error; }
            Reassembly::Complete(data.to_vec())
        }
        u::SAR_START => {
            if !chan.ertm.sdu.is_empty() { return Reassembly::Error; }
            if data.len() < u::SDULEN_SIZE { return Reassembly::Error; }
            let total = u16::from_le_bytes([data[0], data[1]]);
            let body = &data[u::SDULEN_SIZE..];
            if total > chan.imtu { return Reassembly::Error; }
            // A start piece already holding the whole SDU contradicts its own
            // segmentation state.
            if body.len() >= total as usize { return Reassembly::Error; }
            chan.ertm.sdu_len = total;
            chan.ertm.sdu = body.to_vec();
            Reassembly::Incomplete
        }
        u::SAR_CONTINUE => {
            if chan.ertm.sdu.is_empty() { return Reassembly::Error; }
            chan.ertm.sdu.extend_from_slice(data);
            if chan.ertm.sdu.len() >= chan.ertm.sdu_len as usize { return Reassembly::Error; }
            Reassembly::Incomplete
        }
        u::SAR_END => {
            if chan.ertm.sdu.is_empty() { return Reassembly::Error; }
            chan.ertm.sdu.extend_from_slice(data);
            if chan.ertm.sdu.len() != chan.ertm.sdu_len as usize { return Reassembly::Error; }
            Reassembly::Complete(core::mem::take(&mut chan.ertm.sdu))
        }
        _ => Reassembly::Error,
    }
}

/// Cut an SDU into credit-mode frames. The first frame spends two of its
/// payload bytes on the length prefix, so it carries that much less data; every
/// later frame fills the whole PDU. # C: O(n)
pub fn segment_le_sdu(sdu: &[u8], remote_mps: u16) -> Option<Vec<Vec<u8>>> {
    let mps = remote_mps as usize;
    if mps <= u::SDULEN_SIZE { return None; }
    if sdu.len() > u::DEFAULT_MAX_SDU_SIZE as usize { return None; }
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut first = true;
    loop {
        let room = if first { mps - u::SDULEN_SIZE } else { mps };
        let take = core::cmp::min(room, sdu.len() - off);
        let mut frame = Vec::with_capacity(take + u::SDULEN_SIZE);
        if first { frame.extend_from_slice(&(sdu.len() as u16).to_le_bytes()); }
        frame.extend_from_slice(&sdu[off..off + take]);
        out.push(frame);
        off += take;
        first = false;
        if off >= sdu.len() { break; }
    }
    Some(out)
}

#[cfg(test)]
#[path = "tests/sar.rs"]
mod tests;
