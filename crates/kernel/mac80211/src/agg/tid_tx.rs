// The transmit side of one aggregation session: the negotiation, the
// originator's window, and the teardown.
//
// The session is not usable the moment the request goes out. Frames sent
// under a session the peer has not yet agreed to are discarded by the peer,
// so the state machine has an explicit operational step and the transmit path
// consults it rather than the mere existence of the session.

extern crate alloc;

use super::window::TxWindow;
use crate::limits;

/// Where one outgoing session is in its negotiation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TxAggState {
    /// Nothing yet; frames go out unaggregated.
    #[default]
    Idle,
    /// A request has gone out and the response has not come back.
    WantStart,
    /// The peer agreed; frames may be aggregated.
    Operational,
    /// A teardown has gone out.
    WantStop,
}

/// One outgoing session.
#[derive(Clone, Copy, Debug)]
pub struct TidTx {
    pub state: TxAggState,
    pub win: TxWindow,
    /// Token this session's request carried, so a response for an older
    /// attempt is not mistaken for this one's.
    pub dialog_token: u8,
    /// Requests sent so far.
    pub tries: u32,
    /// Monotonic nanoseconds the outstanding request went out at.
    pub request_at_ns: u64,
    /// Monotonic nanoseconds of the last frame sent under the session.
    pub last_tx_ns: u64,
    /// Buffer size the peer agreed to.
    pub buf_size: u16,
    /// Frames seen on this traffic identifier before a session was worth
    /// setting up.
    pub pending_count: u32,
}

impl TidTx {
    /// A session that has not started. # C: O(1)
    pub fn new(ssn: u16) -> Self {
        Self {
            state: TxAggState::Idle,
            win: TxWindow::new(ssn, limits::DEFAULT_AGG_BUF_SIZE),
            dialog_token: 0, tries: 0, request_at_ns: 0, last_tx_ns: 0,
            buf_size: limits::DEFAULT_AGG_BUF_SIZE, pending_count: 0,
        }
    }

    /// Whether enough traffic has gone by to be worth a session. Setting one
    /// up for a traffic identifier that carries two frames a minute costs
    /// more in exchanges than it saves. # C: O(1)
    pub fn should_start(&self) -> bool {
        self.state == TxAggState::Idle && self.pending_count >= limits::AGG_START_THRESHOLD
    }

    /// A request is going out. # C: O(1)
    pub fn request_sent(&mut self, dialog_token: u8, now_ns: u64) {
        self.state = TxAggState::WantStart;
        self.dialog_token = dialog_token;
        self.tries += 1;
        self.request_at_ns = now_ns;
    }

    /// The peer answered. A response carrying a different token belongs to an
    /// attempt this session has already abandoned and is ignored. # C: O(1)
    pub fn response(&mut self, dialog_token: u8, accepted: bool, buf_size: u16) -> bool {
        if self.state != TxAggState::WantStart || dialog_token != self.dialog_token {
            return false;
        }
        if !accepted { self.state = TxAggState::Idle; self.tries = 0; return true; }
        let size = if buf_size == 0 { limits::DEFAULT_AGG_BUF_SIZE }
                   else { buf_size.min(limits::MAX_AGG_BUF_SIZE) };
        self.buf_size = size;
        self.win = TxWindow::new(self.win.next_sn, size);
        self.state = TxAggState::Operational;
        self.tries = 0;
        true
    }

    /// Whether the outstanding request has waited too long. # C: O(1)
    pub fn request_timed_out(&self, now_ns: u64) -> bool {
        self.state == TxAggState::WantStart
            && now_ns.saturating_sub(self.request_at_ns) >= limits::ADDBA_RESP_TIMEOUT_NS
    }

    /// Whether another request is worth sending. # C: O(1)
    pub fn may_retry(&self) -> bool { self.tries < limits::ADDBA_MAX_TRIES }

    /// Whether frames may go out aggregated right now. # C: O(1)
    pub fn is_operational(&self) -> bool { self.state == TxAggState::Operational }

    /// Tear the session down. # C: O(1)
    pub fn stop(&mut self) {
        self.state = TxAggState::WantStop;
        self.pending_count = 0;
    }

    /// The teardown completed. # C: O(1)
    pub fn stopped(&mut self) {
        self.state = TxAggState::Idle;
        self.tries = 0;
        self.pending_count = 0;
    }

    /// Whether the session has carried nothing for long enough to drop.
    /// # C: O(1)
    pub fn is_idle(&self, now_ns: u64) -> bool {
        self.is_operational()
            && now_ns.saturating_sub(self.last_tx_ns) >= limits::AGG_SESSION_TIMEOUT_NS
    }
}
