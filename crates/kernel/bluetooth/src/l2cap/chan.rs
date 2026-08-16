//! The channel: its identity, its state, the configuration it has agreed, and
//! the two bit sets that record how far configuration and the retransmission
//! protocol have progressed.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::bt::{BdAddr, BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BT_CLOSED, BT_CONFIG, BT_CONNECT, BT_CONNECT2, BT_CONNECTED, BT_DISCONN, BT_LISTEN, BT_OPEN, BT_SECURITY_LOW};
use crate::uapi::l2cap as u;

// ---- configuration progress bits --------------------------------------------

/// A configuration request has been sent and its response is outstanding.
pub const CONF_REQ_SENT: u32 = 1 << 0;
/// The peer's proposal has been accepted: our receive direction is settled.
pub const CONF_INPUT_DONE: u32 = 1 << 1;
/// Our proposal has been accepted: our transmit direction is settled.
pub const CONF_OUTPUT_DONE: u32 = 1 << 2;
/// An MTU has been agreed.
pub const CONF_MTU_DONE: u32 = 1 << 3;
/// A transmission mode has been agreed.
pub const CONF_MODE_DONE: u32 = 1 << 4;
/// A connect response is pending, so configuration may not start yet.
pub const CONF_CONNECT_PEND: u32 = 1 << 5;
/// The peer asked for no frame check sequence, which makes it optional for us
/// too.
pub const CONF_RECV_NO_FCS: u32 = 1 << 6;
/// This channel will not renegotiate its mode: a peer proposing a different one
/// is refused rather than answered with a counter-proposal.
pub const CONF_STATE2_DEVICE: u32 = 1 << 7;
/// An extended window size option was received, which overrides the window in
/// the retransmission option.
pub const CONF_EWS_RECV: u32 = 1 << 8;
/// We answered pending and owe the peer a final response.
pub const CONF_LOC_CONF_PEND: u32 = 1 << 9;
/// The peer answered pending and owes us a final response.
pub const CONF_REM_CONF_PEND: u32 = 1 << 10;
/// Configuration has not completed; cleared once both directions are done.
pub const CONF_NOT_COMPLETE: u32 = 1 << 11;

// ---- retransmission protocol bits -------------------------------------------

/// A selective reject has been sent and the missing frames are awaited.
pub const CONN_SREJ_SENT: u32 = 1 << 0;
/// A poll has been sent and its final-bit answer is awaited.
pub const CONN_WAIT_F: u32 = 1 << 1;
/// A selective reject action is in progress.
pub const CONN_SREJ_ACT: u32 = 1 << 2;
/// The next supervisory frame must carry the poll bit.
pub const CONN_SEND_PBIT: u32 = 1 << 3;
/// The peer has declared itself busy; transmission is held.
pub const CONN_REMOTE_BUSY: u32 = 1 << 4;
/// We are busy and have told, or will tell, the peer so.
pub const CONN_LOCAL_BUSY: u32 = 1 << 5;
/// A reject action is in progress.
pub const CONN_REJ_ACT: u32 = 1 << 6;
/// The next frame must carry the final bit.
pub const CONN_SEND_FBIT: u32 = 1 << 7;
/// A receiver-not-ready frame has been sent.
pub const CONN_RNR_SENT: u32 = 1 << 8;

// ---- channel flags ----------------------------------------------------------

pub const FLAG_ROLE_SWITCH: u32 = 1 << 0;
pub const FLAG_FORCE_ACTIVE: u32 = 1 << 1;
pub const FLAG_FORCE_RELIABLE: u32 = 1 << 2;
pub const FLAG_FLUSHABLE: u32 = 1 << 3;
/// The extended control field is in force on this channel.
pub const FLAG_EXT_CTRL: u32 = 1 << 4;
pub const FLAG_EFS_ENABLE: u32 = 1 << 5;
/// Incoming connections are held in `BT_CONNECT2` for the owner to accept.
pub const FLAG_DEFER_SETUP: u32 = 1 << 6;
pub const FLAG_LE_CONN_REQ_SENT: u32 = 1 << 7;
pub const FLAG_ECRED_CONN_REQ_SENT: u32 = 1 << 8;
pub const FLAG_PENDING_SECURITY: u32 = 1 << 9;
pub const FLAG_HOLD_HCI_CONN: u32 = 1 << 10;
pub const FLAG_DEL: u32 = 1 << 11;

/// Buffer size a channel accumulates a multi-part configuration request into. A
/// request that would overflow it is rejected rather than truncated.
pub const CONF_BUF_SIZE: usize = 64;

/// Retransmission-protocol runtime state, live only while a channel runs in
/// enhanced retransmission or streaming mode.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ErtmState {
    pub tx_state: u8,
    pub rx_state: u8,
    /// Sequence number the next transmitted frame will carry.
    pub next_tx_seq: u16,
    /// Oldest sequence number not yet acknowledged.
    pub expected_ack_seq: u16,
    /// Sequence number the next received frame should carry.
    pub expected_tx_seq: u16,
    /// Sequence number the receive buffer has consumed up to.
    pub buffer_seq: u16,
    pub srej_save_reqseq: u16,
    /// Highest sequence number already acknowledged to the peer.
    pub last_acked_seq: u16,
    pub frames_sent: u16,
    pub unacked_frames: u16,
    /// Monitor-timer expiries since the poll was sent.
    pub retry_count: u8,
    /// Declared length of the SDU being reassembled.
    pub sdu_len: u16,
    /// Bytes of that SDU received so far.
    pub sdu: Vec<u8>,
    /// Sequence numbers awaiting selective retransmission, oldest first.
    pub srej_list: Vec<u16>,
    /// Sequence numbers queued for retransmission.
    pub retrans_list: Vec<u16>,
    /// Sequence numbers held out of order while a selective reject is
    /// outstanding.
    pub srej_q: Vec<u16>,
}

/// One frame held in the transmit queue with the sequence number it was given
/// and how many times it has been sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxFrame {
    pub txseq: u16,
    pub sar: u8,
    pub retries: u8,
    pub body: Vec<u8>,
}

/// An L2CAP channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub state: u8,
    pub chan_type: u8,
    pub src: BdAddr,
    pub src_type: u8,
    pub dst: BdAddr,
    pub dst_type: u8,
    /// Service multiplexer, zero on a fixed channel.
    pub psm: u16,
    /// Identifier this end receives on.
    pub scid: u16,
    /// Identifier the peer receives on.
    pub dcid: u16,
    /// Largest SDU this end will accept.
    pub imtu: u16,
    /// Largest SDU the peer will accept.
    pub omtu: u16,
    pub flush_to: u16,
    pub mode: u8,
    pub fcs: u8,
    pub sec_level: u8,
    /// Identifier of the signalling exchange this channel is waiting on.
    pub ident: u8,
    /// Accumulated options of a multi-part configuration request.
    pub conf_req: Vec<u8>,
    pub num_conf_req: u8,
    pub num_conf_rsp: u8,
    pub tx_win: u16,
    pub tx_win_max: u16,
    pub ack_win: u16,
    pub max_tx: u8,
    pub retrans_timeout: u16,
    pub monitor_timeout: u16,
    /// Largest PDU this end will accept.
    pub mps: u16,
    /// Largest PDU the peer will accept.
    pub remote_mps: u16,
    pub remote_tx_win: u16,
    pub remote_max_tx: u8,
    /// Frames this end may still send before it needs a further grant.
    pub tx_credits: u16,
    /// Frames the peer may still send before it needs a further grant.
    pub rx_credits: u16,
    /// Receive buffer space known to be free, or `None` when unknown.
    pub rx_avail: Option<usize>,
    pub conf_state: u32,
    pub conn_state: u32,
    pub flags: u32,
    pub local_id: u8,
    pub local_stype: u8,
    pub local_msdu: u16,
    pub local_sdu_itime: u32,
    pub local_acc_lat: u32,
    pub local_flush_to: u32,
    pub remote_id: u8,
    pub remote_stype: u8,
    pub remote_msdu: u16,
    pub remote_sdu_itime: u32,
    pub remote_acc_lat: u32,
    pub remote_flush_to: u32,
    pub ertm: ErtmState,
    /// Frames sent and not yet acknowledged, oldest first.
    pub tx_q: Vec<TxFrame>,
    /// Index into `tx_q` of the first frame not yet transmitted.
    pub tx_send_head: usize,
    /// Bytes of an inbound credit-mode SDU received so far.
    pub le_sdu: Vec<u8>,
    /// Declared length of that SDU.
    pub le_sdu_len: u16,
}

impl Default for Channel {
    fn default() -> Channel { Channel::new() }
}

impl Channel {
    /// A channel with the defaults a freshly created one starts from: the
    /// window, retry count and timeouts the protocol specifies, the lowest
    /// security level, and configuration marked incomplete. # C: O(1)
    pub fn new() -> Channel {
        Channel {
            state: BT_OPEN, chan_type: u::CHAN_CONN_ORIENTED,
            src: BdAddr::default(), src_type: BDADDR_BREDR,
            dst: BdAddr::default(), dst_type: BDADDR_BREDR,
            psm: 0, scid: 0, dcid: 0,
            imtu: u::DEFAULT_MTU, omtu: u::DEFAULT_MTU, flush_to: u::DEFAULT_FLUSH_TO,
            mode: u::MODE_BASIC, fcs: u::FCS_CRC16, sec_level: BT_SECURITY_LOW, ident: 0,
            conf_req: Vec::new(), num_conf_req: 0, num_conf_rsp: 0,
            tx_win: u::DEFAULT_TX_WINDOW, tx_win_max: u::DEFAULT_TX_WINDOW,
            ack_win: u::DEFAULT_TX_WINDOW, max_tx: u::DEFAULT_MAX_TX,
            retrans_timeout: u::DEFAULT_RETRANS_TO, monitor_timeout: u::DEFAULT_MONITOR_TO,
            mps: 0, remote_mps: 0,
            remote_tx_win: u::DEFAULT_TX_WINDOW, remote_max_tx: u::DEFAULT_MAX_TX,
            tx_credits: 0, rx_credits: 0, rx_avail: None,
            conf_state: CONF_NOT_COMPLETE, conn_state: 0, flags: FLAG_FORCE_ACTIVE,
            local_id: 0, local_stype: u::SERV_NOTRAFIC, local_msdu: 0,
            local_sdu_itime: 0, local_acc_lat: 0, local_flush_to: 0,
            remote_id: 0, remote_stype: u::SERV_NOTRAFIC, remote_msdu: 0,
            remote_sdu_itime: 0, remote_acc_lat: 0, remote_flush_to: 0,
            ertm: ErtmState::default(), tx_q: Vec::new(), tx_send_head: 0,
            le_sdu: Vec::new(), le_sdu_len: 0,
        }
    }

    /// Whether a configuration progress bit is set. # C: O(1)
    pub fn conf(&self, bit: u32) -> bool { self.conf_state & bit != 0 }
    /// Set a configuration progress bit. # C: O(1)
    pub fn set_conf(&mut self, bit: u32) { self.conf_state |= bit; }
    /// Clear a configuration progress bit. # C: O(1)
    pub fn clear_conf(&mut self, bit: u32) { self.conf_state &= !bit; }

    /// Whether a retransmission-protocol bit is set. # C: O(1)
    pub fn cs(&self, bit: u32) -> bool { self.conn_state & bit != 0 }
    /// Set a retransmission-protocol bit. # C: O(1)
    pub fn set_cs(&mut self, bit: u32) { self.conn_state |= bit; }
    /// Clear a retransmission-protocol bit. # C: O(1)
    pub fn clear_cs(&mut self, bit: u32) { self.conn_state &= !bit; }
    /// Clear a retransmission-protocol bit, reporting whether it had been set.
    /// # C: O(1)
    pub fn take_cs(&mut self, bit: u32) -> bool { let had = self.cs(bit); self.conn_state &= !bit; had }

    /// Whether a channel flag is set. # C: O(1)
    pub fn flag(&self, bit: u32) -> bool { self.flags & bit != 0 }
    /// Set a channel flag. # C: O(1)
    pub fn set_flag(&mut self, bit: u32) { self.flags |= bit; }
    /// Clear a channel flag. # C: O(1)
    pub fn clear_flag(&mut self, bit: u32) { self.flags &= !bit; }

    /// Whether the extended control field is in force. # C: O(1)
    pub fn ext_ctrl(&self) -> bool { self.flag(FLAG_EXT_CTRL) }

    /// Whether the channel runs one of the two credit-based modes, which share
    /// their flow control and differ only in how they are set up. # C: O(1)
    pub fn is_credit_mode(&self) -> bool { self.mode == u::MODE_LE_FLOWCTL || self.mode == u::MODE_EXT_FLOWCTL }

    /// Whether the channel runs a mode with a sequence-numbered transmit
    /// window. # C: O(1)
    pub fn is_ertm(&self) -> bool { self.mode == u::MODE_ERTM }

    /// Whether the channel's address type names an LE peer. # C: O(1)
    pub fn is_le(&self) -> bool { self.dst_type == BDADDR_LE_PUBLIC || self.dst_type == BDADDR_LE_RANDOM }

    /// Whether both configuration directions have settled, which is the
    /// condition for the channel to open. # C: O(1)
    pub fn conf_complete(&self) -> bool { self.conf(CONF_INPUT_DONE) && self.conf(CONF_OUTPUT_DONE) }

    /// Move to a new state. A move out of a closed channel is refused: a closed
    /// channel is terminal, and reopening one in place is how a stale peer
    /// response resurrects a channel its owner already dropped. # C: O(1)
    pub fn set_state(&mut self, state: u8) -> bool {
        if self.state == BT_CLOSED && state != BT_CLOSED { return false; }
        self.state = state;
        true
    }

    /// Whether the channel is in a state that accepts data. # C: O(1)
    pub fn can_send(&self) -> bool { self.state == BT_CONNECTED }

    /// Whether a configuration command may be processed in the current state.
    /// A channel that is connecting, configuring or already open may
    /// reconfigure; anything else names a channel the peer should not be
    /// configuring. # C: O(1)
    pub fn conf_allowed(&self) -> bool {
        matches!(self.state, BT_CONFIG | BT_CONNECT2 | BT_CONNECTED)
    }

    /// Whether the channel is in one of the states a connect attempt may leave
    /// it in. # C: O(1)
    pub fn is_connecting(&self) -> bool { matches!(self.state, BT_CONNECT | BT_CONNECT2 | BT_CONFIG) }

    /// Whether the channel is torn down or on the way there. # C: O(1)
    pub fn is_closing(&self) -> bool { matches!(self.state, BT_DISCONN | BT_CLOSED) }

    /// Whether the channel is a listener. # C: O(1)
    pub fn is_listening(&self) -> bool { self.state == BT_LISTEN }

    /// The frame check sequence to use once both directions have settled. It
    /// applies only to the two sequence-numbered modes, and only when neither
    /// end asked to do without it. # C: O(1)
    pub fn default_fcs(&self) -> u8 {
        if self.mode != u::MODE_ERTM && self.mode != u::MODE_STREAMING { u::FCS_NONE }
        else if !self.conf(CONF_RECV_NO_FCS) { u::FCS_CRC16 }
        else { self.fcs }
    }

    /// Apply the settled frame check sequence. # C: O(1)
    pub fn set_default_fcs(&mut self) { self.fcs = self.default_fcs(); }

    /// Choose the control-field width and the window ceiling. A window larger
    /// than the basic field can express needs the extended field, and is only
    /// available when the peer advertises it; otherwise the window is clamped
    /// to what the basic field holds. # C: O(1)
    pub fn txwin_setup(&mut self, ews_supported: bool) {
        if self.tx_win > u::DEFAULT_TX_WINDOW && ews_supported {
            self.set_flag(FLAG_EXT_CTRL);
            self.tx_win_max = u::DEFAULT_EXT_WINDOW;
        } else {
            if self.tx_win > u::DEFAULT_TX_WINDOW { self.tx_win = u::DEFAULT_TX_WINDOW; }
            self.tx_win_max = u::DEFAULT_TX_WINDOW;
        }
        self.ack_win = self.tx_win;
    }

    /// Initialise the retransmission state for a channel about to open in a
    /// sequence-numbered mode. # C: O(1)
    pub fn ertm_init(&mut self) {
        self.ertm = ErtmState::default();
        self.ertm.tx_state = u::TX_STATE_XMIT;
        self.ertm.rx_state = u::RX_STATE_RECV;
        self.tx_q.clear();
        self.tx_send_head = 0;
    }
}

#[cfg(test)]
#[path = "tests/chan.rs"]
mod tests;
