//! Multiplexer commands.
//!
//! Every one travels in a UIH frame on DLCI 0, behind a two-byte header giving
//! the command and its payload length. The DLCI field of the port-negotiation,
//! line-status and modem-status payloads is address-encoded with the
//! command/response bit set — it is not the raw DLCI, and treating it as one
//! addresses the wrong channel by a factor of four.

use alloc::vec::Vec;

use crate::uapi::rfcomm as u;
use super::frame;

/// Parameter-negotiation payload.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Pn {
    pub dlci: u8,
    pub flow_ctrl: u8,
    pub priority: u8,
    pub ack_timer: u8,
    pub mtu: u16,
    pub max_retrans: u8,
    pub credits: u8,
}

/// Port-negotiation payload. `dlci` is the raw DLCI; the address encoding is
/// applied on the wire.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Rpn {
    pub dlci: u8,
    pub bit_rate: u8,
    pub line_settings: u8,
    pub flow_ctrl: u8,
    pub xon_char: u8,
    pub xoff_char: u8,
    pub param_mask: u16,
}

/// Remote line status payload.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Rls { pub dlci: u8, pub status: u8 }

/// Modem status payload. The signal byte carries its own extended-address bit,
/// which is set on every transmission.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Msc { pub dlci: u8, pub v24_sig: u8 }

/// A decoded multiplexer command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mcc {
    Pn(Pn),
    /// A full port-negotiation payload.
    Rpn(Rpn),
    /// A one-byte port-negotiation payload, which asks for the current values
    /// rather than setting any.
    RpnQuery(u8),
    Rls(Rls),
    Msc(Msc),
    Fcon,
    Fcoff,
    Test(Vec<u8>),
    /// Non-supported-command, naming the MCC type byte that was refused.
    Nsc(u8),
    /// A command this end does not implement, kept so the session can refuse it
    /// by type rather than dropping it.
    Unknown(u8),
}

/// A command together with the direction bit that says whether it is a request
/// or the answer to one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MccFrame { pub cr: bool, pub cmd: Mcc }

impl Mcc {
    /// The MCC type byte this command is carried under. # C: O(1)
    pub fn mcc_type(&self) -> u8 {
        match self {
            Mcc::Pn(_) => u::RFCOMM_PN,
            Mcc::Rpn(_) | Mcc::RpnQuery(_) => u::RFCOMM_RPN,
            Mcc::Rls(_) => u::RFCOMM_RLS,
            Mcc::Msc(_) => u::RFCOMM_MSC,
            Mcc::Fcon => u::RFCOMM_FCON,
            Mcc::Fcoff => u::RFCOMM_FCOFF,
            Mcc::Test(_) => u::RFCOMM_TEST,
            Mcc::Nsc(_) => u::RFCOMM_NSC,
            Mcc::Unknown(t) => *t,
        }
    }

    /// The payload bytes that follow the MCC header. # C: O(n) in payload length
    pub fn payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Mcc::Pn(p) => {
                v.extend_from_slice(&[p.dlci, p.flow_ctrl, p.priority, p.ack_timer]);
                v.extend_from_slice(&p.mtu.to_le_bytes());
                v.extend_from_slice(&[p.max_retrans, p.credits]);
            }
            Mcc::Rpn(r) => {
                v.extend_from_slice(&[u::addr(true, r.dlci), r.bit_rate, r.line_settings,
                                      r.flow_ctrl, r.xon_char, r.xoff_char]);
                v.extend_from_slice(&r.param_mask.to_le_bytes());
            }
            Mcc::RpnQuery(dlci) => v.push(u::addr(true, *dlci)),
            Mcc::Rls(r) => v.extend_from_slice(&[u::addr(true, r.dlci), r.status]),
            Mcc::Msc(m) => v.extend_from_slice(&[u::addr(true, m.dlci), m.v24_sig | 0x01]),
            Mcc::Fcon | Mcc::Fcoff => {}
            Mcc::Test(p) => v.extend_from_slice(p),
            Mcc::Nsc(t) => v.push(*t),
            Mcc::Unknown(_) => {}
        }
        v
    }
}

/// Encode a multiplexer command as a complete frame addressed to DLCI 0 of the
/// session whose control-channel address byte is `ctl_addr`. # C: O(n)
pub fn encode(ctl_addr: u8, cr: bool, cmd: &Mcc) -> Vec<u8> {
    let payload = cmd.payload();
    let mut body = Vec::with_capacity(payload.len() + u::RFCOMM_MCC_LEN);
    body.push(u::mcc_type(cr, cmd.mcc_type()));
    body.push(u::len8(payload.len()));
    body.extend_from_slice(&payload);
    frame::encode_uih(ctl_addr, false, &body)
}

/// Decode a multiplexer command out of a control-channel UIH payload. A payload
/// too short for the command it names is rejected rather than zero-filled.
/// # C: O(n)
pub fn decode(body: &[u8]) -> Option<MccFrame> {
    if body.len() < u::RFCOMM_MCC_LEN { return None; }
    let cr = u::test_cr(body[0]);
    let ty = u::get_mcc_type(body[0]);
    let declared = u::get_mcc_len(body[1]);
    let rest = &body[u::RFCOMM_MCC_LEN..];
    let avail = core::cmp::min(declared, rest.len());
    let p = &rest[..avail];
    let cmd = match ty {
        u::RFCOMM_PN => {
            if p.len() < u::RFCOMM_PN_LEN { return None; }
            Mcc::Pn(Pn {
                dlci: p[0], flow_ctrl: p[1], priority: p[2], ack_timer: p[3],
                mtu: u16::from_le_bytes([p[4], p[5]]), max_retrans: p[6], credits: p[7],
            })
        }
        u::RFCOMM_RPN => {
            if p.len() == 1 { Mcc::RpnQuery(u::get_dlci(p[0])) }
            else if p.len() >= u::RFCOMM_RPN_LEN {
                Mcc::Rpn(Rpn {
                    dlci: u::get_dlci(p[0]), bit_rate: p[1], line_settings: p[2],
                    flow_ctrl: p[3], xon_char: p[4], xoff_char: p[5],
                    param_mask: u16::from_le_bytes([p[6], p[7]]),
                })
            } else { return None; }
        }
        u::RFCOMM_RLS => {
            if p.len() < u::RFCOMM_RLS_LEN { return None; }
            Mcc::Rls(Rls { dlci: u::get_dlci(p[0]), status: p[1] })
        }
        u::RFCOMM_MSC => {
            if p.len() < u::RFCOMM_MSC_LEN { return None; }
            Mcc::Msc(Msc { dlci: u::get_dlci(p[0]), v24_sig: p[1] })
        }
        u::RFCOMM_FCON => Mcc::Fcon,
        u::RFCOMM_FCOFF => Mcc::Fcoff,
        u::RFCOMM_TEST => Mcc::Test(p.to_vec()),
        u::RFCOMM_NSC => { if p.is_empty() { return None; } Mcc::Nsc(p[0]) }
        other => Mcc::Unknown(other),
    };
    Some(MccFrame { cr, cmd })
}
