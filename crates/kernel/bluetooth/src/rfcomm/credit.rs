//! Credit-based flow control.
//!
//! Each direction of a DLC holds a credit count: one credit is one frame. The
//! transmitter may not send without a credit, and the receiver hands credits
//! back by setting the poll/final bit on a frame whose first payload byte is
//! the grant.
//!
//! Two invariants matter more than the rest, because breaking either produces a
//! link that misbehaves silently rather than failing:
//! - transmission stops dead at zero credits, and only a grant releases it;
//! - a top-up grants the DIFFERENCE between the ceiling and what is held, never
//!   the ceiling itself, or the peer's count runs away from this one's.

use crate::uapi::rfcomm as u;
use super::mcc::Pn;

/// Credits a DLC hands itself each pass when credit flow is off. Without credit
/// flow the peer's window is unknown, so this is a self-imposed batch size, not
/// a negotiated allowance.
pub const NONCFC_TX_CREDITS: u16 = 5;

/// The credit state of one DLC.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CreditFlow {
    /// Tri-state: unknown until negotiated, then disabled or the ceiling.
    pub cfc: i16,
    pub rx_credits: u16,
    pub tx_credits: u16,
    /// Set when transmission must stop: no credits, or the peer asked for a
    /// halt through the modem-status flow bit.
    pub tx_throttled: bool,
    /// Set when this end cannot accept data, which suppresses top-ups.
    pub rx_throttled: bool,
}

impl Default for CreditFlow {
    fn default() -> CreditFlow { CreditFlow::new() }
}

impl CreditFlow {
    /// The state a DLC starts in: credit flow off, and the default receive
    /// allowance already granted. # C: O(1)
    pub fn new() -> CreditFlow {
        CreditFlow {
            cfc: u::RFCOMM_CFC_DISABLED,
            rx_credits: u::RFCOMM_DEFAULT_CREDITS as u16,
            tx_credits: 0,
            tx_throttled: false,
            rx_throttled: false,
        }
    }

    /// Whether credit flow is on for this DLC. # C: O(1)
    pub fn enabled(&self) -> bool { self.cfc > 0 }

    /// The credit ceiling, which is the enabled marker itself. # C: O(1)
    pub fn ceiling(&self) -> u16 { if self.cfc > 0 { self.cfc as u16 } else { 0 } }

    /// Adopt a parameter-negotiation payload. Credit flow comes on when the
    /// payload carries the request value and the session has not already
    /// negotiated it off, or when it carries the response value; anything else
    /// turns it off and parks transmission until the modem-status exchange
    /// releases it. Returns the session-wide setting this DLC implies.
    /// # C: O(1)
    pub fn apply_pn(&mut self, pn: &Pn, session_cfc: i16) -> i16 {
        let on = (pn.flow_ctrl == u::RFCOMM_PN_CFC_REQ && session_cfc != u::RFCOMM_CFC_DISABLED)
            || pn.flow_ctrl == u::RFCOMM_PN_CFC_RSP;
        if on {
            self.cfc = u::RFCOMM_CFC_ENABLED;
            self.tx_credits = pn.credits as u16;
        } else {
            self.cfc = u::RFCOMM_CFC_DISABLED;
            self.tx_throttled = true;
        }
        self.cfc
    }

    /// Take the credit byte off a frame that carried one. Returns the payload
    /// with the grant removed; a frame whose poll/final bit is set but which
    /// carries no byte is a truncated frame and yields nothing. # C: O(1)
    pub fn take_grant<'a>(&mut self, pf: bool, payload: &'a [u8]) -> Option<&'a [u8]> {
        if !(pf && self.enabled()) { return Some(payload); }
        let (grant, rest) = payload.split_first()?;
        self.tx_credits = self.tx_credits.saturating_add(*grant as u16);
        if self.tx_credits > 0 { self.tx_throttled = false; }
        Some(rest)
    }

    /// Whether a frame may be transmitted now. # C: O(1)
    pub fn can_send(&self) -> bool { !self.tx_throttled && self.tx_credits > 0 }

    /// Account for one transmitted frame. Reaching zero parks the transmitter
    /// so a later send does not spin looking for credit that is not there.
    /// # C: O(1)
    pub fn on_frame_sent(&mut self) {
        self.tx_credits = self.tx_credits.saturating_sub(1);
        if self.enabled() && self.tx_credits == 0 { self.tx_throttled = true; }
    }

    /// Account for one received data frame. # C: O(1)
    pub fn on_frame_received(&mut self) { self.rx_credits = self.rx_credits.saturating_sub(1); }

    /// Hand the peer whatever it takes to restore the ceiling, once the held
    /// allowance has fallen to a quarter of it. Returns the grant to send, or
    /// nothing when no top-up is due. # C: O(1)
    pub fn topup(&mut self) -> Option<u8> {
        if !self.enabled() || self.rx_throttled { return None; }
        let ceiling = self.ceiling();
        if self.rx_credits > ceiling >> 2 { return None; }
        let grant = ceiling - self.rx_credits;
        self.rx_credits = ceiling;
        Some(grant as u8)
    }

    /// Refill the self-imposed batch a DLC without credit flow transmits in.
    /// # C: O(1)
    pub fn refill_noncfc(&mut self) {
        if !self.enabled() { self.tx_credits = NONCFC_TX_CREDITS; }
    }
}
