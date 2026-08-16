//! Configuration request and response framing, and the option list they carry.
//!
//! Options are parsed into raw type/value records here; deciding what a value
//! means, and what to answer, is `config`'s job.

extern crate alloc;
use alloc::vec::Vec;

use super::codec::{Reader, Writer};
use crate::uapi::l2cap as u;

/// One configuration option as it appeared on the wire: its type with the hint
/// bit split off, and its value bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawOpt {
    /// Option type with the hint bit masked off.
    pub otype: u8,
    /// Whether the sender marked the option as a hint, which permits ignoring
    /// it silently instead of reporting it as unknown.
    pub hint: bool,
    pub val: Vec<u8>,
}

impl RawOpt {
    /// A non-hint option with a 16-bit value. # C: O(1)
    pub fn le16(otype: u8, v: u16) -> RawOpt { RawOpt { otype, hint: false, val: v.to_le_bytes().to_vec() } }

    /// A non-hint option with a single-byte value. # C: O(1)
    pub fn byte(otype: u8, v: u8) -> RawOpt { RawOpt { otype, hint: false, val: [v].to_vec() } }

    /// Value read as a 16-bit word, or `None` when the width is wrong.
    /// # C: O(1)
    pub fn as_le16(&self) -> Option<u16> {
        if self.val.len() != u::CONF_MTU_LEN { return None; }
        Some(u16::from_le_bytes([self.val[0], self.val[1]]))
    }

    /// Value read as a single byte, or `None` when the width is wrong.
    /// # C: O(1)
    pub fn as_byte(&self) -> Option<u8> {
        if self.val.len() != 1 { return None; }
        Some(self.val[0])
    }

    /// Encoded width including the two-byte option header. # C: O(1)
    pub fn wire_len(&self) -> usize { u::CONF_OPT_SIZE + self.val.len() }
}

/// The outcome of walking an option list: the options that parsed, and whether
/// the walk stopped early because an option declared a length past the end of
/// the buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedOpts {
    pub opts: Vec<RawOpt>,
    /// An option overran the buffer. The options before it are still valid; the
    /// remainder of the list is unusable.
    pub truncated: bool,
}

/// Walk an option list. A trailing fragment shorter than an option header ends
/// the list; an option whose declared value runs past the end of the buffer
/// stops the walk and is reported, never parsed from the bytes that happen to
/// follow. # C: O(n)
pub fn parse_opts(buf: &[u8]) -> ParsedOpts {
    let mut opts = Vec::new();
    let mut r = Reader::new(buf);
    while r.remaining() >= u::CONF_OPT_SIZE {
        let raw_type = match r.u8() { Some(v) => v, None => break };
        let olen = match r.u8() { Some(v) => v as usize, None => break };
        let val = match r.bytes(olen) { Some(v) => v, None => return ParsedOpts { opts, truncated: true } };
        opts.push(RawOpt { otype: raw_type & u::CONF_MASK, hint: raw_type & u::CONF_HINT != 0, val: val.to_vec() });
    }
    ParsedOpts { opts, truncated: false }
}

/// Serialise an option list. An option whose value exceeds the largest a
/// configuration option may carry is refused rather than truncated. # C: O(n)
pub fn encode_opts(opts: &[RawOpt]) -> Option<Vec<u8>> {
    let mut w = Writer::new();
    for o in opts {
        if o.val.len() > u::CONF_MAX_SIZE { return None; }
        w.u8(if o.hint { o.otype | u::CONF_HINT } else { o.otype & u::CONF_MASK });
        w.u8(o.val.len() as u8);
        w.bytes(&o.val);
    }
    Some(w.into_vec())
}

/// Retransmission and flow control option: the mode and the parameters that
/// only apply to it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Rfc {
    pub mode: u8,
    pub txwin_size: u8,
    pub max_transmit: u8,
    pub retrans_timeout: u16,
    pub monitor_timeout: u16,
    pub max_pdu_size: u16,
}

impl Rfc {
    /// Parse an RFC value. # C: O(1)
    pub fn decode(val: &[u8]) -> Option<Rfc> {
        if val.len() != u::CONF_RFC_LEN { return None; }
        let mut r = Reader::new(val);
        Some(Rfc {
            mode: r.u8()?, txwin_size: r.u8()?, max_transmit: r.u8()?,
            retrans_timeout: r.le16()?, monitor_timeout: r.le16()?, max_pdu_size: r.le16()?,
        })
    }

    /// Serialise the value. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.mode); w.u8(self.txwin_size); w.u8(self.max_transmit);
        w.le16(self.retrans_timeout); w.le16(self.monitor_timeout); w.le16(self.max_pdu_size);
        w.into_vec()
    }

    /// The option record carrying this value. # C: O(1)
    pub fn opt(&self) -> RawOpt { RawOpt { otype: u::CONF_RFC, hint: false, val: self.encode() } }

    /// A basic-mode value, whose other fields are all unused. # C: O(1)
    pub fn basic() -> Rfc { Rfc { mode: u::MODE_BASIC, ..Rfc::default() } }
}

/// Extended flow specification.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Efs {
    pub id: u8,
    pub stype: u8,
    pub msdu: u16,
    pub sdu_itime: u32,
    pub acc_lat: u32,
    pub flush_to: u32,
}

impl Efs {
    /// Parse an EFS value. # C: O(1)
    pub fn decode(val: &[u8]) -> Option<Efs> {
        if val.len() != u::CONF_EFS_LEN { return None; }
        let mut r = Reader::new(val);
        Some(Efs {
            id: r.u8()?, stype: r.u8()?, msdu: r.le16()?,
            sdu_itime: r.le32()?, acc_lat: r.le32()?, flush_to: r.le32()?,
        })
    }

    /// Serialise the value. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.id); w.u8(self.stype); w.le16(self.msdu);
        w.le32(self.sdu_itime); w.le32(self.acc_lat); w.le32(self.flush_to);
        w.into_vec()
    }

    /// The option record carrying this value. # C: O(1)
    pub fn opt(&self) -> RawOpt { RawOpt { otype: u::CONF_EFS, hint: false, val: self.encode() } }
}

/// Configuration request: the responder's channel identifier, the continuation
/// flag, and the options being proposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfReq {
    pub dcid: u16,
    pub flags: u16,
    pub opts: Vec<u8>,
}

impl ConfReq {
    /// Parse a configuration request. # C: O(n)
    pub fn decode(body: &[u8]) -> Option<ConfReq> {
        if body.len() < u::CONF_REQ_MIN_LEN { return None; }
        let mut r = Reader::new(body);
        let dcid = r.le16()?;
        let flags = r.le16()?;
        Some(ConfReq { dcid, flags, opts: r.rest().to_vec() })
    }

    /// Serialise the request. # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.dcid); w.le16(self.flags); w.bytes(&self.opts);
        w.into_vec()
    }

    /// Whether more options follow in a further request. # C: O(1)
    pub fn more(&self) -> bool { self.flags & u::CONF_FLAG_CONTINUATION != 0 }
}

/// Configuration response: the requester's channel identifier, the
/// continuation flag, the verdict, and any options the verdict refers to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfRsp {
    pub scid: u16,
    pub flags: u16,
    pub result: u16,
    pub opts: Vec<u8>,
}

impl ConfRsp {
    /// Parse a configuration response. # C: O(n)
    pub fn decode(body: &[u8]) -> Option<ConfRsp> {
        if body.len() < u::CONF_RSP_MIN_LEN { return None; }
        let mut r = Reader::new(body);
        let scid = r.le16()?;
        let flags = r.le16()?;
        let result = r.le16()?;
        Some(ConfRsp { scid, flags, result, opts: r.rest().to_vec() })
    }

    /// Serialise the response. # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.scid); w.le16(self.flags); w.le16(self.result); w.bytes(&self.opts);
        w.into_vec()
    }

    /// Whether more options follow in a further response. # C: O(1)
    pub fn more(&self) -> bool { self.flags & u::CONF_FLAG_CONTINUATION != 0 }
}

#[cfg(test)]
#[path = "tests/sig_conf.rs"]
mod tests;
