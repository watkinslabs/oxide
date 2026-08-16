//! LE signalling commands: the connection parameter update, the credit-based
//! connection, credit grants, and the enhanced credit-based variants that carry
//! several channels in one exchange.

extern crate alloc;
use alloc::vec::Vec;

use super::codec::{Reader, Writer};
use crate::uapi::l2cap as u;

/// Connection parameter update request, sent by a peripheral asking the central
/// to change the link timing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConnParamUpdateReq {
    pub min: u16,
    pub max: u16,
    pub latency: u16,
    pub to_multiplier: u16,
}

impl ConnParamUpdateReq {
    /// Parse the request. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<ConnParamUpdateReq> {
        if body.len() != u::CONN_PARAM_UPDATE_REQ_LEN { return None; }
        let mut r = Reader::new(body);
        Some(ConnParamUpdateReq { min: r.le16()?, max: r.le16()?, latency: r.le16()?, to_multiplier: r.le16()? })
    }

    /// Serialise the request. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.min); w.le16(self.max); w.le16(self.latency); w.le16(self.to_multiplier);
        w.into_vec()
    }
}

/// Connection parameter update response: accepted or rejected.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConnParamUpdateRsp {
    pub result: u16,
}

impl ConnParamUpdateRsp {
    /// Parse the response. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<ConnParamUpdateRsp> {
        if body.len() != u::CONN_PARAM_UPDATE_RSP_LEN { return None; }
        let mut r = Reader::new(body);
        Some(ConnParamUpdateRsp { result: r.le16()? })
    }

    /// Serialise the response. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.result);
        w.into_vec()
    }
}

/// Credit-based connection request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeConnReq {
    pub psm: u16,
    pub scid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
}

impl LeConnReq {
    /// Parse the request. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<LeConnReq> {
        if body.len() != u::LE_CONN_REQ_LEN { return None; }
        let mut r = Reader::new(body);
        Some(LeConnReq { psm: r.le16()?, scid: r.le16()?, mtu: r.le16()?, mps: r.le16()?, credits: r.le16()? })
    }

    /// Serialise the request. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.psm); w.le16(self.scid); w.le16(self.mtu); w.le16(self.mps); w.le16(self.credits);
        w.into_vec()
    }
}

/// Credit-based connection response.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeConnRsp {
    pub dcid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
    pub result: u16,
}

impl LeConnRsp {
    /// Parse the response. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<LeConnRsp> {
        if body.len() != u::LE_CONN_RSP_LEN { return None; }
        let mut r = Reader::new(body);
        Some(LeConnRsp { dcid: r.le16()?, mtu: r.le16()?, mps: r.le16()?, credits: r.le16()?, result: r.le16()? })
    }

    /// Serialise the response. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.dcid); w.le16(self.mtu); w.le16(self.mps); w.le16(self.credits); w.le16(self.result);
        w.into_vec()
    }
}

/// A credit grant: how many further frames the sender will accept on `cid`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeCredits {
    pub cid: u16,
    pub credits: u16,
}

impl LeCredits {
    /// Parse the grant. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<LeCredits> {
        if body.len() != u::LE_CREDITS_LEN { return None; }
        let mut r = Reader::new(body);
        Some(LeCredits { cid: r.le16()?, credits: r.le16()? })
    }

    /// Serialise the grant. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.cid); w.le16(self.credits);
        w.into_vec()
    }
}

/// Read a trailing array of channel identifiers. The remaining bytes must be a
/// whole number of identifiers, and there is a hard ceiling on how many one
/// command may name. # C: O(n)
fn cid_array(r: &mut Reader<'_>) -> Option<Vec<u16>> {
    if r.remaining() % u::CID_WIDTH != 0 { return None; }
    let n = r.remaining() / u::CID_WIDTH;
    if n > u::ECRED_MAX_CID { return None; }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n { v.push(r.le16()?); }
    Some(v)
}

/// Enhanced credit-based connection request: one set of parameters covering
/// every channel it names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcredConnReq {
    pub psm: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
    pub scids: Vec<u16>,
}

impl EcredConnReq {
    /// Parse the request. # C: O(n)
    pub fn decode(body: &[u8]) -> Option<EcredConnReq> {
        if body.len() < u::ECRED_CONN_REQ_HDR_LEN { return None; }
        let mut r = Reader::new(body);
        let psm = r.le16()?;
        let mtu = r.le16()?;
        let mps = r.le16()?;
        let credits = r.le16()?;
        Some(EcredConnReq { psm, mtu, mps, credits, scids: cid_array(&mut r)? })
    }

    /// Serialise the request. # C: O(n)
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.scids.len() > u::ECRED_MAX_CID { return None; }
        let mut w = Writer::new();
        w.le16(self.psm); w.le16(self.mtu); w.le16(self.mps); w.le16(self.credits);
        for c in &self.scids { w.le16(*c); }
        Some(w.into_vec())
    }
}

/// Enhanced credit-based connection response. A zero identifier in the array
/// means that one channel of the request was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcredConnRsp {
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
    pub result: u16,
    pub dcids: Vec<u16>,
}

impl EcredConnRsp {
    /// Parse the response. # C: O(n)
    pub fn decode(body: &[u8]) -> Option<EcredConnRsp> {
        if body.len() < u::ECRED_CONN_RSP_HDR_LEN { return None; }
        let mut r = Reader::new(body);
        let mtu = r.le16()?;
        let mps = r.le16()?;
        let credits = r.le16()?;
        let result = r.le16()?;
        Some(EcredConnRsp { mtu, mps, credits, result, dcids: cid_array(&mut r)? })
    }

    /// Serialise the response. # C: O(n)
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.dcids.len() > u::ECRED_MAX_CID { return None; }
        let mut w = Writer::new();
        w.le16(self.mtu); w.le16(self.mps); w.le16(self.credits); w.le16(self.result);
        for c in &self.dcids { w.le16(*c); }
        Some(w.into_vec())
    }
}

/// Enhanced credit-based reconfigure request: new receive parameters for a set
/// of already-open channels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcredReconfReq {
    pub mtu: u16,
    pub mps: u16,
    pub scids: Vec<u16>,
}

impl EcredReconfReq {
    /// Parse the request. # C: O(n)
    pub fn decode(body: &[u8]) -> Option<EcredReconfReq> {
        if body.len() < u::ECRED_RECONF_REQ_HDR_LEN { return None; }
        let mut r = Reader::new(body);
        let mtu = r.le16()?;
        let mps = r.le16()?;
        Some(EcredReconfReq { mtu, mps, scids: cid_array(&mut r)? })
    }

    /// Serialise the request. # C: O(n)
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.scids.len() > u::ECRED_MAX_CID { return None; }
        let mut w = Writer::new();
        w.le16(self.mtu); w.le16(self.mps);
        for c in &self.scids { w.le16(*c); }
        Some(w.into_vec())
    }
}

/// Enhanced credit-based reconfigure response.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EcredReconfRsp {
    pub result: u16,
}

impl EcredReconfRsp {
    /// Parse the response. # C: O(1)
    pub fn decode(body: &[u8]) -> Option<EcredReconfRsp> {
        if body.len() != u::ECRED_RECONF_RSP_LEN { return None; }
        let mut r = Reader::new(body);
        Some(EcredReconfRsp { result: r.le16()? })
    }

    /// Serialise the response. # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.le16(self.result);
        w.into_vec()
    }
}

/// Whether a signalling command code belongs on the LE signalling channel. The
/// two channels carry disjoint command sets apart from disconnect and command
/// reject, and a command arriving on the wrong one is refused. # C: O(1)
pub fn le_sig_code(code: u8) -> bool {
    matches!(code,
        u::COMMAND_REJ | u::DISCONN_REQ | u::DISCONN_RSP
        | u::CONN_PARAM_UPDATE_REQ | u::CONN_PARAM_UPDATE_RSP
        | u::LE_CONN_REQ | u::LE_CONN_RSP | u::LE_CREDITS
        | u::ECRED_CONN_REQ | u::ECRED_CONN_RSP
        | u::ECRED_RECONF_REQ | u::ECRED_RECONF_RSP)
}

/// Whether a signalling command code belongs on the BR/EDR signalling channel.
/// # C: O(1)
pub fn bredr_sig_code(code: u8) -> bool {
    matches!(code,
        u::COMMAND_REJ | u::CONN_REQ | u::CONN_RSP | u::CONF_REQ | u::CONF_RSP
        | u::DISCONN_REQ | u::DISCONN_RSP | u::ECHO_REQ | u::ECHO_RSP
        | u::INFO_REQ | u::INFO_RSP)
}

#[cfg(test)]
#[path = "tests/sig_le.rs"]
mod tests;
