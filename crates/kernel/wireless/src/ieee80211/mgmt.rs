// Management frame bodies. Each parser takes the frame body — the bytes
// after the MAC header — and returns the fixed fields plus the element
// stream that follows them, or nothing when the body is too short for the
// fixed part it claims to have.

use super::status::{ReasonCode, StatusCode};

/// Capability information bits, as they appear in beacons, probe responses
/// and association frames.
pub mod capability {
    pub const ESS: u16 = 1 << 0;
    pub const IBSS: u16 = 1 << 1;
    pub const CF_POLLABLE: u16 = 1 << 2;
    pub const CF_POLL_REQUEST: u16 = 1 << 3;
    pub const PRIVACY: u16 = 1 << 4;
    pub const SHORT_PREAMBLE: u16 = 1 << 5;
    pub const PBCC: u16 = 1 << 6;
    pub const CHANNEL_AGILITY: u16 = 1 << 7;
    pub const SPECTRUM_MGMT: u16 = 1 << 8;
    pub const QOS: u16 = 1 << 9;
    pub const SHORT_SLOT_TIME: u16 = 1 << 10;
    pub const APSD: u16 = 1 << 11;
    pub const RADIO_MEASURE: u16 = 1 << 12;
    pub const EPD: u16 = 1 << 13;
    pub const DEL_BACK: u16 = 1 << 14;
    pub const IMM_BACK: u16 = 1 << 15;
}

/// Authentication algorithm numbers.
pub mod auth_alg {
    pub const OPEN: u16 = 0;
    pub const SHARED_KEY: u16 = 1;
    pub const FT: u16 = 2;
    pub const SAE: u16 = 3;
    pub const FILS_SK: u16 = 4;
    pub const FILS_SK_PFS: u16 = 5;
    pub const FILS_PK: u16 = 6;
    pub const NETWORK_EAP: u16 = 0x80;
}

/// Action-frame categories.
pub mod action_category {
    pub const SPECTRUM_MGMT: u8 = 0;
    pub const QOS: u8 = 1;
    pub const DLS: u8 = 2;
    pub const BLOCK_ACK: u8 = 3;
    pub const PUBLIC: u8 = 4;
    pub const RADIO_MEASUREMENT: u8 = 5;
    pub const FT: u8 = 6;
    pub const HT: u8 = 7;
    pub const SA_QUERY: u8 = 8;
    pub const PROTECTED_DUAL: u8 = 9;
    pub const WNM: u8 = 10;
    pub const SELF_PROTECTED: u8 = 15;
    pub const MESH: u8 = 13;
    pub const VHT: u8 = 21;
    pub const VENDOR_SPECIFIC_PROTECTED: u8 = 126;
    pub const VENDOR_SPECIFIC: u8 = 127;
}

/// Block-ack action codes inside the block-ack category.
pub mod block_ack_action {
    pub const ADDBA_REQ: u8 = 0;
    pub const ADDBA_RESP: u8 = 1;
    pub const DELBA: u8 = 2;
}

/// Fixed part of a beacon or probe response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeaconBody<'a> {
    pub timestamp: u64,
    pub beacon_int: u16,
    pub capability: u16,
    pub elements: &'a [u8],
}

impl<'a> BeaconBody<'a> {
    /// Fixed field width before the element stream.
    pub const FIXED_LEN: usize = 12;

    /// Parse a beacon or probe-response body. # C: O(1)
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let fixed = body.get(..Self::FIXED_LEN)?;
        Some(Self {
            timestamp: u64::from_le_bytes(fixed[..8].try_into().ok()?),
            beacon_int: u16::from_le_bytes([fixed[8], fixed[9]]),
            capability: u16::from_le_bytes([fixed[10], fixed[11]]),
            elements: &body[Self::FIXED_LEN..],
        })
    }
    /// Whether the network claims privacy, which decides whether a connect
    /// without keys can succeed at all. # C: O(1)
    pub fn privacy(&self) -> bool { self.capability & capability::PRIVACY != 0 }
}

/// Fixed part of an authentication frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthBody<'a> {
    pub alg: u16,
    pub transaction: u16,
    pub status: StatusCode,
    pub elements: &'a [u8],
}

impl<'a> AuthBody<'a> {
    /// Fixed field width before the element stream.
    pub const FIXED_LEN: usize = 6;

    /// Parse an authentication body. # C: O(1)
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let f = body.get(..Self::FIXED_LEN)?;
        Some(Self {
            alg: u16::from_le_bytes([f[0], f[1]]),
            transaction: u16::from_le_bytes([f[2], f[3]]),
            status: u16::from_le_bytes([f[4], f[5]]),
            elements: &body[Self::FIXED_LEN..],
        })
    }
}

/// Fixed part of an association or reassociation request. A reassociation
/// request carries the current AP address between the fixed fields and the
/// elements, so the two are parsed by the same function with a flag rather
/// than by two parsers that can drift apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssocReqBody<'a> {
    pub capability: u16,
    pub listen_interval: u16,
    pub current_ap: Option<super::hdr::MacAddr>,
    pub elements: &'a [u8],
}

impl<'a> AssocReqBody<'a> {
    /// Fixed field width of an association request.
    pub const FIXED_LEN: usize = 4;
    /// Fixed field width of a reassociation request.
    pub const REASSOC_FIXED_LEN: usize = 10;

    /// Parse an (re)association request body. # C: O(1)
    pub fn parse(body: &'a [u8], reassoc: bool) -> Option<Self> {
        let fixed_len = if reassoc { Self::REASSOC_FIXED_LEN } else { Self::FIXED_LEN };
        let f = body.get(..fixed_len)?;
        Some(Self {
            capability: u16::from_le_bytes([f[0], f[1]]),
            listen_interval: u16::from_le_bytes([f[2], f[3]]),
            current_ap: if reassoc { super::hdr::MacAddr::from_slice(&f[4..]) } else { None },
            elements: &body[fixed_len..],
        })
    }
}

/// Association identifier field. The two top bits are always set on the air
/// and are not part of the identifier.
pub const AID_MASK: u16 = 0x3fff;
/// Largest association identifier an AP may hand out.
pub const MAX_AID: u16 = 2007;

/// Fixed part of an association or reassociation response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssocRespBody<'a> {
    pub capability: u16,
    pub status: StatusCode,
    /// Association identifier with the two reserved top bits removed.
    pub aid: u16,
    pub elements: &'a [u8],
}

impl<'a> AssocRespBody<'a> {
    /// Fixed field width before the element stream.
    pub const FIXED_LEN: usize = 6;

    /// Parse an (re)association response body. # C: O(1)
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let f = body.get(..Self::FIXED_LEN)?;
        Some(Self {
            capability: u16::from_le_bytes([f[0], f[1]]),
            status: u16::from_le_bytes([f[2], f[3]]),
            aid: u16::from_le_bytes([f[4], f[5]]) & AID_MASK,
            elements: &body[Self::FIXED_LEN..],
        })
    }
}

/// Deauthenticate or disassociate body: one reason code, then optional
/// elements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReasonBody<'a> {
    pub reason: ReasonCode,
    pub elements: &'a [u8],
}

impl<'a> ReasonBody<'a> {
    /// Fixed field width before the element stream.
    pub const FIXED_LEN: usize = 2;

    /// Parse a deauthenticate or disassociate body. # C: O(1)
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let f = body.get(..Self::FIXED_LEN)?;
        Some(Self { reason: u16::from_le_bytes([f[0], f[1]]),
                    elements: &body[Self::FIXED_LEN..] })
    }
}

/// An ADDBA request: the parameters both ends must agree on before a block
/// ack session exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddbaReq {
    pub dialog_token: u8,
    pub params: u16,
    pub timeout: u16,
    /// Sequence number the originator's window starts at.
    pub start_seq_num: u16,
}

/// An ADDBA response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddbaResp {
    pub dialog_token: u8,
    pub status: StatusCode,
    pub params: u16,
    pub timeout: u16,
}

/// A DELBA: which direction is torn down and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delba {
    pub params: u16,
    pub reason: ReasonCode,
}

/// Block-ack parameter-set field layout.
pub mod ba_params {
    /// Set when the session delivers whole MSDUs rather than fragments.
    pub const AMSDU: u16 = 1 << 0;
    /// Set for an immediate block ack, clear for a delayed one.
    pub const POLICY: u16 = 1 << 1;
    pub const TID_MASK: u16 = 0x003c;
    pub const TID_SHIFT: u32 = 2;
    pub const BUFSIZE_MASK: u16 = 0xffc0;
    pub const BUFSIZE_SHIFT: u32 = 6;
    /// Set in a DELBA when the sender is the originator of the session.
    pub const DELBA_INITIATOR: u16 = 1 << 11;
    pub const DELBA_TID_MASK: u16 = 0xf000;
    pub const DELBA_TID_SHIFT: u32 = 12;

    /// Traffic identifier out of an ADDBA parameter set. # C: O(1)
    pub fn tid(params: u16) -> u8 { ((params & TID_MASK) >> TID_SHIFT) as u8 }
    /// Reorder buffer size out of an ADDBA parameter set. # C: O(1)
    pub fn buf_size(params: u16) -> u16 { (params & BUFSIZE_MASK) >> BUFSIZE_SHIFT }
    /// Traffic identifier out of a DELBA parameter set — a different field
    /// from the ADDBA one, which is why it has its own accessor. # C: O(1)
    pub fn delba_tid(params: u16) -> u8 { ((params & DELBA_TID_MASK) >> DELBA_TID_SHIFT) as u8 }
    /// Build an ADDBA parameter set. # C: O(1)
    pub fn build(tid: u8, buf_size: u16, amsdu: bool, immediate: bool) -> u16 {
        let mut p = ((tid as u16) << TID_SHIFT) & TID_MASK;
        p |= (buf_size << BUFSIZE_SHIFT) & BUFSIZE_MASK;
        if amsdu { p |= AMSDU; }
        if immediate { p |= POLICY; }
        p
    }
}

/// Starting-sequence-control field: the sequence number is the top 12 bits.
pub const SSC_SSN_SHIFT: u32 = 4;

/// Parse a block-ack action frame body, which begins after the category and
/// action code. # C: O(1)
pub fn parse_addba_req(body: &[u8]) -> Option<AddbaReq> {
    let f = body.get(..7)?;
    Some(AddbaReq {
        dialog_token: f[0],
        params: u16::from_le_bytes([f[1], f[2]]),
        timeout: u16::from_le_bytes([f[3], f[4]]),
        start_seq_num: u16::from_le_bytes([f[5], f[6]]) >> SSC_SSN_SHIFT,
    })
}

/// Parse an ADDBA response body. # C: O(1)
pub fn parse_addba_resp(body: &[u8]) -> Option<AddbaResp> {
    let f = body.get(..7)?;
    Some(AddbaResp {
        dialog_token: f[0],
        status: u16::from_le_bytes([f[1], f[2]]),
        params: u16::from_le_bytes([f[3], f[4]]),
        timeout: u16::from_le_bytes([f[5], f[6]]),
    })
}

/// Parse a DELBA body. # C: O(1)
pub fn parse_delba(body: &[u8]) -> Option<Delba> {
    let f = body.get(..4)?;
    Some(Delba { params: u16::from_le_bytes([f[0], f[1]]),
                 reason: u16::from_le_bytes([f[2], f[3]]) })
}
