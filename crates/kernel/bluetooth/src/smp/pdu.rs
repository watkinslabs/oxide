//! The wire codec.
//!
//! A frame is a code byte followed by a fixed-width payload. A frame shorter
//! than its code requires is refused with invalid parameters; trailing bytes
//! past the payload are ignored, which is what lets a peer built against a
//! later revision talk to this one. A code past the defined range is dropped
//! without an answer, because answering an unknown code is a way to be used as
//! an oracle; a code inside the range that is not a command is answered with
//! command-not-supported.

use crate::uapi::bt::{BDADDR_LEN, BdAddr};
use crate::uapi::smp::*;

/// Longest frame the protocol defines: the public key exchange.
pub const SMP_PDU_MAX: usize = SMP_CODE_LEN + SMP_PUBLIC_KEY_LEN;

/// The six-byte body both pairing PDUs carry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PairingCmd {
    pub io_capability: u8,
    pub oob_flag: u8,
    pub auth_req: u8,
    pub max_key_size: u8,
    pub init_key_dist: u8,
    pub resp_key_dist: u8,
}

impl PairingCmd {
    /// Read the body from its six wire bytes. # C: O(1)
    pub fn from_bytes(b: &[u8; SMP_PAIRING_LEN]) -> PairingCmd {
        PairingCmd {
            io_capability: b[0], oob_flag: b[1], auth_req: b[2],
            max_key_size: b[3], init_key_dist: b[4], resp_key_dist: b[5],
        }
    }

    /// Write the body as its six wire bytes. # C: O(1)
    pub fn to_bytes(&self) -> [u8; SMP_PAIRING_LEN] {
        [self.io_capability, self.oob_flag, self.auth_req,
         self.max_key_size, self.init_key_dist, self.resp_key_dist]
    }
}

/// A decoded frame.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Pdu {
    PairingReq(PairingCmd),
    PairingRsp(PairingCmd),
    Confirm([u8; SMP_CONFIRM_LEN]),
    Random([u8; SMP_RANDOM_LEN]),
    Fail(u8),
    EncryptInfo([u8; SMP_ENCRYPT_INFO_LEN]),
    InitiatorIdent { ediv: u16, rand: u64 },
    IdentInfo([u8; SMP_IDENT_INFO_LEN]),
    IdentAddrInfo { addr_type: u8, addr: BdAddr },
    SignInfo([u8; SMP_SIGN_INFO_LEN]),
    SecurityReq(u8),
    PublicKey { x: [u8; SMP_PUBKEY_COORD_LEN], y: [u8; SMP_PUBKEY_COORD_LEN] },
    DhkeyCheck([u8; SMP_DHKEY_CHECK_LEN]),
    KeypressNotify(u8),
}

/// Why a frame could not be decoded.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DecodeErr {
    /// No code byte.
    Empty,
    /// Code past the defined range.
    Unknown,
    /// Code inside the range that names no command.
    NotSupported,
    /// Payload shorter than the code requires.
    BadLength,
}

/// The failure reason to send for a decode error, or `None` when the frame is
/// to be dropped without a reply. # C: O(1)
pub fn err_reason(e: DecodeErr) -> Option<u8> {
    match e {
        DecodeErr::Empty | DecodeErr::Unknown => None,
        DecodeErr::NotSupported => Some(SMP_CMD_NOTSUPP),
        DecodeErr::BadLength => Some(SMP_INVALID_PARAMS),
    }
}

/// Payload width a code requires, or `None` when the code names no command.
/// # C: O(1)
pub fn payload_len(code: u8) -> Option<usize> {
    Some(match code {
        SMP_CMD_PAIRING_REQ | SMP_CMD_PAIRING_RSP => SMP_PAIRING_LEN,
        SMP_CMD_PAIRING_CONFIRM => SMP_CONFIRM_LEN,
        SMP_CMD_PAIRING_RANDOM => SMP_RANDOM_LEN,
        SMP_CMD_PAIRING_FAIL => SMP_FAIL_LEN,
        SMP_CMD_ENCRYPT_INFO => SMP_ENCRYPT_INFO_LEN,
        SMP_CMD_INITIATOR_IDENT => SMP_INITIATOR_IDENT_LEN,
        SMP_CMD_IDENT_INFO => SMP_IDENT_INFO_LEN,
        SMP_CMD_IDENT_ADDR_INFO => SMP_IDENT_ADDR_LEN,
        SMP_CMD_SIGN_INFO => SMP_SIGN_INFO_LEN,
        SMP_CMD_SECURITY_REQ => SMP_SECURITY_REQ_LEN,
        SMP_CMD_PUBLIC_KEY => SMP_PUBLIC_KEY_LEN,
        SMP_CMD_DHKEY_CHECK => SMP_DHKEY_CHECK_LEN,
        SMP_CMD_KEYPRESS_NOTIFY => SMP_KEYPRESS_LEN,
        _ => return None,
    })
}

fn key16(p: &[u8]) -> [u8; SMP_KEY_LEN] {
    let mut k = [0u8; SMP_KEY_LEN];
    k.copy_from_slice(&p[..SMP_KEY_LEN]);
    k
}

fn coord(p: &[u8]) -> [u8; SMP_PUBKEY_COORD_LEN] {
    let mut c = [0u8; SMP_PUBKEY_COORD_LEN];
    c.copy_from_slice(&p[..SMP_PUBKEY_COORD_LEN]);
    c
}

/// Decode a frame. # C: O(1)
pub fn decode(frame: &[u8]) -> Result<Pdu, DecodeErr> {
    let code = *frame.first().ok_or(DecodeErr::Empty)?;
    if code > SMP_CMD_MAX { return Err(DecodeErr::Unknown); }
    let need = payload_len(code).ok_or(DecodeErr::NotSupported)?;
    let p = &frame[SMP_CODE_LEN..];
    if p.len() < need { return Err(DecodeErr::BadLength); }

    Ok(match code {
        SMP_CMD_PAIRING_REQ =>
            Pdu::PairingReq(PairingCmd::from_bytes(p[..SMP_PAIRING_LEN].try_into().unwrap())),
        SMP_CMD_PAIRING_RSP =>
            Pdu::PairingRsp(PairingCmd::from_bytes(p[..SMP_PAIRING_LEN].try_into().unwrap())),
        SMP_CMD_PAIRING_CONFIRM => Pdu::Confirm(key16(p)),
        SMP_CMD_PAIRING_RANDOM => Pdu::Random(key16(p)),
        SMP_CMD_PAIRING_FAIL => Pdu::Fail(p[0]),
        SMP_CMD_ENCRYPT_INFO => Pdu::EncryptInfo(key16(p)),
        SMP_CMD_INITIATOR_IDENT => Pdu::InitiatorIdent {
            ediv: u16::from_le_bytes([p[0], p[1]]),
            rand: u64::from_le_bytes(p[2..SMP_INITIATOR_IDENT_LEN].try_into().unwrap()),
        },
        SMP_CMD_IDENT_INFO => Pdu::IdentInfo(key16(p)),
        SMP_CMD_IDENT_ADDR_INFO => Pdu::IdentAddrInfo {
            addr_type: p[0],
            addr: BdAddr::from_wire(p, 1).ok_or(DecodeErr::BadLength)?,
        },
        SMP_CMD_SIGN_INFO => Pdu::SignInfo(key16(p)),
        SMP_CMD_SECURITY_REQ => Pdu::SecurityReq(p[0]),
        SMP_CMD_PUBLIC_KEY => Pdu::PublicKey {
            x: coord(p),
            y: coord(&p[SMP_PUBKEY_COORD_LEN..]),
        },
        SMP_CMD_DHKEY_CHECK => Pdu::DhkeyCheck(key16(p)),
        SMP_CMD_KEYPRESS_NOTIFY => Pdu::KeypressNotify(p[0]),
        _ => return Err(DecodeErr::NotSupported),
    })
}

impl Pdu {
    /// The code byte this frame carries. # C: O(1)
    pub fn code(&self) -> u8 {
        match self {
            Pdu::PairingReq(_) => SMP_CMD_PAIRING_REQ,
            Pdu::PairingRsp(_) => SMP_CMD_PAIRING_RSP,
            Pdu::Confirm(_) => SMP_CMD_PAIRING_CONFIRM,
            Pdu::Random(_) => SMP_CMD_PAIRING_RANDOM,
            Pdu::Fail(_) => SMP_CMD_PAIRING_FAIL,
            Pdu::EncryptInfo(_) => SMP_CMD_ENCRYPT_INFO,
            Pdu::InitiatorIdent { .. } => SMP_CMD_INITIATOR_IDENT,
            Pdu::IdentInfo(_) => SMP_CMD_IDENT_INFO,
            Pdu::IdentAddrInfo { .. } => SMP_CMD_IDENT_ADDR_INFO,
            Pdu::SignInfo(_) => SMP_CMD_SIGN_INFO,
            Pdu::SecurityReq(_) => SMP_CMD_SECURITY_REQ,
            Pdu::PublicKey { .. } => SMP_CMD_PUBLIC_KEY,
            Pdu::DhkeyCheck(_) => SMP_CMD_DHKEY_CHECK,
            Pdu::KeypressNotify(_) => SMP_CMD_KEYPRESS_NOTIFY,
        }
    }

    /// Total encoded width including the code byte. # C: O(1)
    pub fn encoded_len(&self) -> usize {
        SMP_CODE_LEN + payload_len(self.code()).unwrap_or(0)
    }

    /// Write the frame. `None` when the buffer is too small. # C: O(1)
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.encoded_len();
        if out.len() < n { return None; }
        out[0] = self.code();
        let p = &mut out[SMP_CODE_LEN..n];
        match self {
            Pdu::PairingReq(c) | Pdu::PairingRsp(c) => p.copy_from_slice(&c.to_bytes()),
            Pdu::Confirm(v) | Pdu::Random(v) | Pdu::EncryptInfo(v)
            | Pdu::IdentInfo(v) | Pdu::SignInfo(v) | Pdu::DhkeyCheck(v) => p.copy_from_slice(v),
            Pdu::Fail(v) | Pdu::SecurityReq(v) | Pdu::KeypressNotify(v) => p[0] = *v,
            Pdu::InitiatorIdent { ediv, rand } => {
                p[..2].copy_from_slice(&ediv.to_le_bytes());
                p[2..].copy_from_slice(&rand.to_le_bytes());
            }
            Pdu::IdentAddrInfo { addr_type, addr } => {
                p[0] = *addr_type;
                p[1..1 + BDADDR_LEN].copy_from_slice(addr.as_bytes());
            }
            Pdu::PublicKey { x, y } => {
                p[..SMP_PUBKEY_COORD_LEN].copy_from_slice(x);
                p[SMP_PUBKEY_COORD_LEN..].copy_from_slice(y);
            }
        }
        Some(n)
    }
}
