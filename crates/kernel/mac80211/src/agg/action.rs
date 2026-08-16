// The three action frames that manage a block-ack session, and the decisions
// taken on each.
//
// The decisions are here, separate from the buffers they act on, because they
// are the part with a wire contract: a status code the peer branches on, a
// buffer size that must not exceed what either end can hold, and a traffic
// identifier range outside which no session may exist. A wrong status is not
// a local mistake — the peer acts on it.

use wireless::ieee80211::mgmt::{ba_params, AddbaReq, AddbaResp, Delba};
use wireless::ieee80211::status::status;

use crate::limits;

/// Traffic identifiers a block-ack session may cover. The identifiers above
/// this are reserved for traffic streams with their own admission control and
/// a session on one of them is refused, not silently accepted.
pub const FIRST_TSPEC_TID: u8 = 8;

/// Whether a peer requested the immediate policy. The delayed policy is not
/// implemented; a request for it is refused with a parameter error rather
/// than accepted and then treated as immediate, which would have the two ends
/// disagreeing about when an acknowledgement is due. # C: O(1)
pub fn wants_immediate(params: u16) -> bool { params & ba_params::POLICY != 0 }

/// What to answer an incoming session request with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddbaDecision {
    pub status: u16,
    pub tid: u8,
    /// Buffer size to agree on. Meaningful only when the status is success.
    pub buf_size: u16,
    pub ssn: u16,
    pub amsdu: bool,
    pub timeout: u16,
    pub dialog_token: u8,
}

impl AddbaDecision {
    /// Whether the session is being set up. # C: O(1)
    pub fn accepted(&self) -> bool { self.status == status::SUCCESS }
    /// Parameter set to answer with. # C: O(1)
    pub fn resp_params(&self) -> u16 {
        ba_params::build(self.tid, self.buf_size, self.amsdu, true)
    }
}

/// Decide on an incoming request. `max_local` is the largest buffer this
/// radio will hold. A request naming no buffer size gets the largest — zero
/// is not a size, and honouring it literally makes a session that can never
/// release anything. # C: O(1)
pub fn on_addba_req(req: &AddbaReq, max_local: u16) -> AddbaDecision {
    let tid = ba_params::tid(req.params);
    let amsdu = req.params & ba_params::AMSDU != 0;
    let max_buf = max_local.clamp(limits::MIN_AGG_BUF_SIZE, limits::MAX_AGG_BUF_SIZE);
    let asked = ba_params::buf_size(req.params);

    let mut d = AddbaDecision {
        status: status::SUCCESS, tid, buf_size: 0, ssn: req.start_seq_num,
        amsdu, timeout: req.timeout, dialog_token: req.dialog_token,
    };
    if tid >= FIRST_TSPEC_TID { d.status = status::REQUEST_DECLINED; return d; }
    if !wants_immediate(req.params) { d.status = status::INVALID_QOS_PARAM; return d; }
    // The parameter field is ten bits wide, so a request can never name more
    // than the protocol allows; what it CAN name is more than this radio
    // holds, which is agreed down rather than refused.
    d.buf_size = if asked == 0 { max_buf } else { asked.min(max_buf) };
    d
}

/// What an incoming response means to the originator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddbaOutcome {
    pub tid: u8,
    pub accepted: bool,
    pub buf_size: u16,
    pub dialog_token: u8,
}

/// Read a response. A response that says success but names a buffer of zero,
/// or a traffic identifier outside the range, is treated as a refusal: acting
/// on it would set up a session neither end can use. # C: O(1)
pub fn on_addba_resp(resp: &AddbaResp) -> AddbaOutcome {
    let tid = ba_params::tid(resp.params);
    let buf_size = ba_params::buf_size(resp.params);
    let sane = tid < FIRST_TSPEC_TID && buf_size > 0
        && buf_size <= limits::MAX_AGG_BUF_SIZE && wants_immediate(resp.params);
    AddbaOutcome {
        tid,
        accepted: resp.status == status::SUCCESS && sane,
        buf_size,
        dialog_token: resp.dialog_token,
    }
}

/// What an incoming teardown names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelbaOutcome {
    pub tid: u8,
    /// Whether the sender was the originator of the session, which decides
    /// WHICH of the two half-sessions this tears down.
    pub initiator: bool,
    pub reason: u16,
}

/// Read a teardown. # C: O(1)
pub fn on_delba(delba: &Delba) -> DelbaOutcome {
    DelbaOutcome {
        tid: ba_params::delba_tid(delba.params),
        initiator: delba.params & ba_params::DELBA_INITIATOR != 0,
        reason: delba.reason,
    }
}

/// Parameter set for a request this radio originates. # C: O(1)
pub fn req_params(tid: u8, buf_size: u16, amsdu: bool) -> u16 {
    ba_params::build(tid, buf_size, amsdu, true)
}
