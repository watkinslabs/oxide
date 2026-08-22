//! L2CAP sequence-numbered wire framing and frame-check sequence handling.
//!
//! The FCS covers the basic L2CAP header, control field, and payload. It is
//! appended only when channel configuration selects CRC-16; receive verifies
//! the complete frame before exposing the control field or payload.

extern crate alloc;
use alloc::vec::Vec;

use super::chan::Channel;
use super::codec::{Hdr, Writer};
use super::ctrl::{ctrl_size, Ctrl};
use super::ertm_tx::OutFrame;
use crate::uapi::l2cap as u;

/// Encode one sequence-numbered frame, including its basic header and FCS.
/// # C: O(n)
pub fn encode(cid: u16, chan: &Channel, frame: &OutFrame) -> Option<Vec<u8>> {
    let ext = chan.ext_ctrl();
    let ctl = frame.ctrl.pack(ext);
    let fcs_len = if chan.fcs == u::FCS_CRC16 { u::FCS_SIZE } else { 0 };
    let payload_len = ctrl_size(ext).checked_add(frame.body.len())?.checked_add(fcs_len)?;
    if payload_len > u16::MAX as usize { return None; }

    let mut w = Writer::new();
    Hdr { len: payload_len as u16, cid }.encode(&mut w);
    w.bytes(&ctl[..ctrl_size(ext)]);
    w.bytes(&frame.body);
    let mut out = w.into_vec();
    if chan.fcs == u::FCS_CRC16 {
        let fcs = crc::crc16(&out);
        out.extend_from_slice(&fcs.to_le_bytes());
    }
    Some(out)
}

/// Verify and split one received sequence-numbered frame. Corrupt, truncated,
/// overlong, and undersized-FCS frames are refused before state-machine input.
/// # C: O(1)
pub fn decode<'a>(chan: &Channel, buf: &'a [u8]) -> Option<(u16, Ctrl, &'a [u8])> {
    let hdr = Hdr::decode(buf)?;
    let body = buf.get(u::HDR_SIZE..)?;
    if body.len() != hdr.len as usize { return None; }
    let ext = chan.ext_ctrl();
    let ctl_len = ctrl_size(ext);
    let fcs_len = if chan.fcs == u::FCS_CRC16 { u::FCS_SIZE } else { 0 };
    if body.len() < ctl_len + fcs_len { return None; }
    if chan.fcs == u::FCS_CRC16 {
        let split = buf.len().checked_sub(u::FCS_SIZE)?;
        let received = u16::from_le_bytes([buf[split], buf[split + 1]]);
        if crc::crc16(&buf[..split]) != received { return None; }
    }
    let ctrl = Ctrl::unpack(&body[..ctl_len], ext)?;
    let end = body.len() - fcs_len;
    Some((hdr.cid, ctrl, &body[ctl_len..end]))
}

#[cfg(test)]
#[path = "tests/fcs.rs"]
mod tests;
