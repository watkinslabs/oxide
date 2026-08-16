//! BR/EDR signalling commands other than configuration: command reject in its
//! three forms, connect, disconnect, echo and the information exchange.

extern crate alloc;
use alloc::vec::Vec;

use super::codec::{Reader, Writer};
use crate::uapi::l2cap as u;

/// A command reject. The reason selects the payload, so a reject carrying the
/// wrong number of bytes for its reason is malformed rather than a reject with
/// missing fields.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CommandRej {
    /// The command code was not recognised, or the command was refused whole.
    NotUnderstood,
    /// The command was longer than the signalling MTU; the reject carries the
    /// largest packet the sender will accept.
    MtuExceeded { max_mtu: u16 },
    /// One or both channel identifiers named no channel.
    InvalidCid { scid: u16, dcid: u16 },
}

impl CommandRej {
    /// Parse a reject payload. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<CommandRej> {
        let mut r = Reader::new(body);
        let reason = r.le16()?;
        let v = match reason {
            u::REJ_NOT_UNDERSTOOD => CommandRej::NotUnderstood,
            u::REJ_MTU_EXCEEDED => CommandRej::MtuExceeded { max_mtu: r.le16()? },
            u::REJ_INVALID_CID => CommandRej::InvalidCid { scid: r.le16()?, dcid: r.le16()? },
            _ => return None,
        };
        if !r.is_empty() { return None; }
        Some(v)
    }

    /// Serialise the reject payload. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match *self {
            CommandRej::NotUnderstood => w.le16(u::REJ_NOT_UNDERSTOOD),
            CommandRej::MtuExceeded { max_mtu } => { w.le16(u::REJ_MTU_EXCEEDED); w.le16(max_mtu); }
            CommandRej::InvalidCid { scid, dcid } => { w.le16(u::REJ_INVALID_CID); w.le16(scid); w.le16(dcid); }
        }
        w.into_vec()
    }

    /// The reason code this reject reports. # C: O(1)
    pub fn reason(&self) -> u16 {
        match *self {
            CommandRej::NotUnderstood => u::REJ_NOT_UNDERSTOOD,
            CommandRej::MtuExceeded { .. } => u::REJ_MTU_EXCEEDED,
            CommandRej::InvalidCid { .. } => u::REJ_INVALID_CID,
        }
    }
}

/// Connect request: the service the initiator wants and the identifier it will
/// answer on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConnReq {
    pub psm: u16,
    pub scid: u16,
}

impl ConnReq {
    /// Parse a connect request. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<ConnReq> {
        if body.len() != u::CONN_REQ_LEN { return None; }
        let mut r = Reader::new(body);
        Some(ConnReq { psm: r.le16()?, scid: r.le16()? })
    }

    /// Serialise the request. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.psm); w.le16(self.scid);
        w.into_vec()
    }
}

/// Connect response. `dcid` is the responder's identifier and is meaningful
/// only once `result` is success.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConnRsp {
    pub dcid: u16,
    pub scid: u16,
    pub result: u16,
    pub status: u16,
}

impl ConnRsp {
    /// Parse a connect response. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<ConnRsp> {
        if body.len() != u::CONN_RSP_LEN { return None; }
        let mut r = Reader::new(body);
        Some(ConnRsp { dcid: r.le16()?, scid: r.le16()?, result: r.le16()?, status: r.le16()? })
    }

    /// Serialise the response. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.dcid); w.le16(self.scid); w.le16(self.result); w.le16(self.status);
        w.into_vec()
    }
}

/// Disconnect request or response; both carry the same pair.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Disconn {
    pub dcid: u16,
    pub scid: u16,
}

impl Disconn {
    /// Parse a disconnect request or response. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<Disconn> {
        if body.len() != u::DISCONN_LEN { return None; }
        let mut r = Reader::new(body);
        Some(Disconn { dcid: r.le16()?, scid: r.le16()? })
    }

    /// Serialise it. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.dcid); w.le16(self.scid);
        w.into_vec()
    }
}

/// Echo request or response payload: opaque bytes echoed back unchanged.
/// # C: O(n)
pub fn echo_encode(data: &[u8]) -> Vec<u8> { data.to_vec() }

/// Information request: which of the three property sets the peer is asking
/// about.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InfoReq {
    pub itype: u16,
}

impl InfoReq {
    /// Parse an information request. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<InfoReq> {
        if body.len() != u::INFO_REQ_LEN { return None; }
        let mut r = Reader::new(body);
        Some(InfoReq { itype: r.le16()? })
    }

    /// Serialise the request. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.itype);
        w.into_vec()
    }
}

/// Information response: the type echoed back, a result, and the property
/// bytes, which are absent when the result is not success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfoRsp {
    pub itype: u16,
    pub result: u16,
    pub data: Vec<u8>,
}

impl InfoRsp {
    /// Parse an information response. # C: O(n)
    pub fn decode(body: &[u8]) -> Option<InfoRsp> {
        if body.len() < u::INFO_RSP_MIN_LEN { return None; }
        let mut r = Reader::new(body);
        let itype = r.le16()?;
        let result = r.le16()?;
        Some(InfoRsp { itype, result, data: r.rest().to_vec() })
    }

    /// Serialise the response. # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.itype); w.le16(self.result); w.bytes(&self.data);
        w.into_vec()
    }

    /// The extended feature mask a successful feature-mask response carries, or
    /// `None` when this response is of another type, failed, or is too short to
    /// hold one. # C: O(1)
    pub fn feat_mask(&self) -> Option<u32> {
        if self.itype != u::IT_FEAT_MASK || self.result != u::IR_SUCCESS { return None; }
        if self.data.len() < u::FEAT_MASK_LEN { return None; }
        Some(u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
    }

    /// The supported-fixed-channel mask a successful fixed-channel response
    /// carries. Only the first byte is defined; the rest is reserved.
    /// # C: O(1)
    pub fn fixed_chan_mask(&self) -> Option<u8> {
        if self.itype != u::IT_FIXED_CHAN || self.result != u::IR_SUCCESS { return None; }
        if self.data.is_empty() { return None; }
        Some(self.data[0])
    }

    /// A feature-mask response. # C: O(1)
    pub fn feat_mask_rsp(mask: u32) -> InfoRsp {
        InfoRsp { itype: u::IT_FEAT_MASK, result: u::IR_SUCCESS, data: mask.to_le_bytes().to_vec() }
    }

    /// A fixed-channel response, padded to the full mask width the reserved
    /// bytes occupy. # C: O(1)
    pub fn fixed_chan_rsp(mask: u8) -> InfoRsp {
        let mut data = Vec::new();
        data.push(mask);
        data.resize(u::FIXED_CHAN_MASK_LEN, 0);
        InfoRsp { itype: u::IT_FIXED_CHAN, result: u::IR_SUCCESS, data }
    }

    /// A refusal of an information type this host does not answer. # C: O(1)
    pub fn not_supported(itype: u16) -> InfoRsp {
        InfoRsp { itype, result: u::IR_NOTSUPP, data: Vec::new() }
    }
}

/// The feature mask this host advertises. Enhanced retransmission, streaming
/// and the frame check sequence are all implemented, so all three are claimed
/// alongside the fixed-channel and extended-window bits. # C: O(1)
pub fn local_feat_mask() -> u32 {
    u::FEAT_ERTM | u::FEAT_STREAMING | u::FEAT_FCS | u::FEAT_FIXED_CHAN | u::FEAT_EXT_WINDOW
}

/// Whether a transmission mode is usable given what the peer advertises. A mode
/// needs support at both ends; anything outside the two negotiable modes is
/// never selected this way. # C: O(1)
pub fn mode_supported(mode: u8, remote_feat_mask: u32) -> bool {
    let both = remote_feat_mask & local_feat_mask();
    match mode {
        u::MODE_ERTM => both & u::FEAT_ERTM != 0,
        u::MODE_STREAMING => both & u::FEAT_STREAMING != 0,
        _ => false,
    }
}

/// The mode to propose: the one asked for when the peer supports it, and basic
/// otherwise. # C: O(1)
pub fn select_mode(mode: u8, remote_feat_mask: u32) -> u8 {
    match mode {
        u::MODE_STREAMING | u::MODE_ERTM if mode_supported(mode, remote_feat_mask) => mode,
        _ => u::MODE_BASIC,
    }
}

#[cfg(test)]
#[path = "tests/sig_bredr.rs"]
mod tests;
