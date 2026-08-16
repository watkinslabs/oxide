//! One data link connection: the per-channel half of the multiplexer.
//!
//! A DLC is named by its DLCI, which encodes both the server channel and which
//! end of the session opened it, so the two directions of the same channel are
//! different DLCIs and never collide.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::uapi::bt::{BT_OPEN, BT_SECURITY_LOW};
use crate::uapi::rfcomm as u;
use super::credit::CreditFlow;
use super::rpn::PortSettings;

/// One data link connection.
#[derive(Clone, Debug)]
pub struct Dlc {
    pub dlci: u8,
    /// The address byte this end stamps on frames it sends for this DLC.
    pub addr: u8,
    pub state: u8,
    pub priority: u8,
    /// The signals this end reports to the peer.
    pub v24_sig: u8,
    /// The signals the peer last reported.
    pub remote_v24_sig: u8,
    /// Which directions of the modem-status exchange have completed. Data does
    /// not flow until both have.
    pub mscex: u8,
    /// Whether this end opened the DLC.
    pub out: bool,
    pub sec_level: u8,
    pub role_switch: bool,
    pub defer_setup: bool,
    pub mtu: u16,
    pub credit: CreditFlow,
    pub port: PortSettings,
    /// Frames built and waiting for a credit.
    pub tx_queue: VecDeque<Vec<u8>>,
    /// Bit set of the flags in `uapi::rfcomm`.
    pub flags: u32,
}

/// Default priority of a DLC opened by this end.
pub const DLC_DEFAULT_PRIORITY: u8 = 7;

impl Dlc {
    /// A DLC in the state a freshly allocated one starts in: open, unnegotiated,
    /// with the default MTU and the signals a ready port asserts. # C: O(1)
    pub fn new(dlci: u8, addr: u8) -> Dlc {
        Dlc {
            dlci, addr,
            state: BT_OPEN,
            priority: DLC_DEFAULT_PRIORITY,
            v24_sig: u::RFCOMM_V24_RTC | u::RFCOMM_V24_RTR | u::RFCOMM_V24_DV,
            remote_v24_sig: 0,
            mscex: 0,
            out: false,
            sec_level: BT_SECURITY_LOW,
            role_switch: false,
            defer_setup: false,
            mtu: u::RFCOMM_DEFAULT_MTU,
            credit: CreditFlow::new(),
            port: PortSettings::new(),
            tx_queue: VecDeque::new(),
            flags: 0,
        }
    }

    /// The server channel this DLC belongs to. # C: O(1)
    pub fn channel(&self) -> u8 { u::srv_channel(self.dlci) }

    /// Whether a flag bit is set. # C: O(1)
    pub fn flag(&self, bit: u32) -> bool { self.flags & (1 << bit) != 0 }

    /// Set a flag bit, reporting whether it was already set. # C: O(1)
    pub fn set_flag(&mut self, bit: u32) -> bool {
        let was = self.flag(bit);
        self.flags |= 1 << bit;
        was
    }

    /// Clear a flag bit, reporting whether it had been set. # C: O(1)
    pub fn clear_flag(&mut self, bit: u32) -> bool {
        let was = self.flag(bit);
        self.flags &= !(1 << bit);
        was
    }

    /// Whether the modem-status exchange has completed in both directions,
    /// which is the gate on carrying data. # C: O(1)
    pub fn mscex_complete(&self) -> bool { self.mscex == u::RFCOMM_MSCEX_OK }

    /// Stop accepting data from the peer, suppressing credit top-ups. The
    /// throttle state lives in the credit accounting and nowhere else, so a
    /// reader that stops draining cannot leave the two disagreeing. # C: O(1)
    pub fn throttle(&mut self) { self.credit.rx_throttled = true; }

    /// Resume accepting data. # C: O(1)
    pub fn unthrottle(&mut self) { self.credit.rx_throttled = false; }

    /// Whether this end has stopped accepting data. # C: O(1)
    pub fn throttled(&self) -> bool { self.credit.rx_throttled }

    /// The parameter-negotiation payload describing this DLC, as a request when
    /// `cr` is set and as the answer to one otherwise. Credit flow is offered
    /// only when the session has it on, and the two directions carry different
    /// flow-control values so each end can tell a request from a response.
    /// # C: O(1)
    pub fn pn(&self, cr: bool, session_cfc: i16, mtu: u16) -> super::mcc::Pn {
        let (flow_ctrl, credits) = if session_cfc != u::RFCOMM_CFC_DISABLED {
            (if cr { u::RFCOMM_PN_CFC_REQ } else { u::RFCOMM_PN_CFC_RSP }, u::RFCOMM_DEFAULT_CREDITS)
        } else {
            (0, 0)
        };
        super::mcc::Pn {
            dlci: self.dlci,
            flow_ctrl,
            priority: self.priority,
            ack_timer: 0,
            mtu,
            max_retrans: 0,
            credits,
        }
    }
}
