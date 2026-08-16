//! Port negotiation.
//!
//! The parameter mask is the whole of the semantics: a bit that is clear names
//! a parameter the sender is not negotiating, and that parameter keeps the value
//! the port already has. A responder that applies every field of the payload
//! regardless of the mask silently resets a port's line settings each time the
//! peer asks about one unrelated parameter.
//!
//! The reply repeats what was accepted and CLEARS the mask bit of anything that
//! was not, so the requester can see which of its parameters did not take.

use crate::uapi::rfcomm as u;
use super::mcc::Rpn;

/// The line parameters of one port.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PortSettings {
    pub bit_rate: u8,
    pub data_bits: u8,
    pub stop_bits: u8,
    pub parity: u8,
    pub flow_ctrl: u8,
    pub xon_char: u8,
    pub xoff_char: u8,
}

impl Default for PortSettings {
    fn default() -> PortSettings { PortSettings::new() }
}

impl PortSettings {
    /// The values a port reports before anything has negotiated it. # C: O(1)
    pub fn new() -> PortSettings {
        PortSettings {
            bit_rate: u::RFCOMM_RPN_BR_9600,
            data_bits: u::RFCOMM_RPN_DATA_8,
            stop_bits: u::RFCOMM_RPN_STOP_1,
            parity: u::RFCOMM_RPN_PARITY_NONE,
            flow_ctrl: u::RFCOMM_RPN_FLOW_NONE,
            xon_char: u::RFCOMM_RPN_XON_CHAR,
            xoff_char: u::RFCOMM_RPN_XOFF_CHAR,
        }
    }

    /// The line-settings byte these parameters pack into. # C: O(1)
    pub fn line_settings(&self) -> u8 {
        u::rpn_line_settings(self.data_bits, self.stop_bits, self.parity)
    }

    /// Apply the parameters a payload actually names. Every field outside the
    /// mask is left alone. # C: O(1)
    pub fn apply(&mut self, rpn: &Rpn) {
        let m = rpn.param_mask;
        if m & u::RFCOMM_RPN_PM_BITRATE != 0 { self.bit_rate = rpn.bit_rate; }
        if m & u::RFCOMM_RPN_PM_DATA != 0 { self.data_bits = u::get_rpn_data_bits(rpn.line_settings); }
        if m & u::RFCOMM_RPN_PM_STOP != 0 { self.stop_bits = u::get_rpn_stop_bits(rpn.line_settings); }
        if m & u::RFCOMM_RPN_PM_PARITY != 0 { self.parity = u::get_rpn_parity(rpn.line_settings); }
        if m & u::RFCOMM_RPN_PM_FLOW != 0 { self.flow_ctrl = rpn.flow_ctrl; }
        if m & u::RFCOMM_RPN_PM_XON != 0 { self.xon_char = rpn.xon_char; }
        if m & u::RFCOMM_RPN_PM_XOFF != 0 { self.xoff_char = rpn.xoff_char; }
    }

    /// The payload that reports these parameters for `dlci` under `mask`.
    /// # C: O(1)
    pub fn to_rpn(&self, dlci: u8, mask: u16) -> Rpn {
        Rpn {
            dlci,
            bit_rate: self.bit_rate,
            line_settings: self.line_settings(),
            flow_ctrl: self.flow_ctrl,
            xon_char: self.xon_char,
            xoff_char: self.xoff_char,
            param_mask: mask,
        }
    }
}

/// The values this end will carry: eight data bits, one stop bit, no parity, no
/// flow-control lines, the standard software flow-control characters, and any
/// bit rate the field can express.
///
/// A request naming something else is answered with the value that WILL be
/// used and with that parameter's mask bit cleared, which is how the peer
/// learns its request did not take.
/// # C: O(1)
pub fn negotiate(req: &Rpn) -> Rpn {
    let m = req.param_mask;
    let mut mask = u::RFCOMM_RPN_PM_ALL;
    let mut out = PortSettings {
        bit_rate: 0, data_bits: 0, stop_bits: 0, parity: 0,
        flow_ctrl: 0, xon_char: 0, xoff_char: 0,
    };

    if m & u::RFCOMM_RPN_PM_BITRATE != 0 {
        out.bit_rate = req.bit_rate;
        if out.bit_rate > u::RFCOMM_RPN_BR_230400 {
            out.bit_rate = u::RFCOMM_RPN_BR_9600;
            mask ^= u::RFCOMM_RPN_PM_BITRATE;
        }
    }
    if m & u::RFCOMM_RPN_PM_DATA != 0 {
        out.data_bits = u::get_rpn_data_bits(req.line_settings);
        if out.data_bits != u::RFCOMM_RPN_DATA_8 {
            out.data_bits = u::RFCOMM_RPN_DATA_8;
            mask ^= u::RFCOMM_RPN_PM_DATA;
        }
    }
    if m & u::RFCOMM_RPN_PM_STOP != 0 {
        out.stop_bits = u::get_rpn_stop_bits(req.line_settings);
        if out.stop_bits != u::RFCOMM_RPN_STOP_1 {
            out.stop_bits = u::RFCOMM_RPN_STOP_1;
            mask ^= u::RFCOMM_RPN_PM_STOP;
        }
    }
    if m & u::RFCOMM_RPN_PM_PARITY != 0 {
        out.parity = u::get_rpn_parity(req.line_settings);
        if out.parity != u::RFCOMM_RPN_PARITY_NONE {
            out.parity = u::RFCOMM_RPN_PARITY_NONE;
            mask ^= u::RFCOMM_RPN_PM_PARITY;
        }
    }
    if m & u::RFCOMM_RPN_PM_FLOW != 0 {
        out.flow_ctrl = req.flow_ctrl;
        if out.flow_ctrl != u::RFCOMM_RPN_FLOW_NONE {
            out.flow_ctrl = u::RFCOMM_RPN_FLOW_NONE;
            mask ^= u::RFCOMM_RPN_PM_FLOW;
        }
    }
    if m & u::RFCOMM_RPN_PM_XON != 0 {
        out.xon_char = req.xon_char;
        if out.xon_char != u::RFCOMM_RPN_XON_CHAR {
            out.xon_char = u::RFCOMM_RPN_XON_CHAR;
            mask ^= u::RFCOMM_RPN_PM_XON;
        }
    }
    if m & u::RFCOMM_RPN_PM_XOFF != 0 {
        out.xoff_char = req.xoff_char;
        if out.xoff_char != u::RFCOMM_RPN_XOFF_CHAR {
            out.xoff_char = u::RFCOMM_RPN_XOFF_CHAR;
            mask ^= u::RFCOMM_RPN_PM_XOFF;
        }
    }

    out.to_rpn(req.dlci, mask)
}

/// The answer to a one-byte port-negotiation query, which reports this end's
/// standing values under the full mask. # C: O(1)
pub fn query_reply(dlci: u8) -> Rpn { PortSettings::new().to_rpn(dlci, u::RFCOMM_RPN_PM_ALL) }
