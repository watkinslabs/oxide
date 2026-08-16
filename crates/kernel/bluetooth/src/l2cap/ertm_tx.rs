//! The retransmission transmitter: the send window, acknowledgement
//! processing, retransmission, and the two-state transmitter machine.
//!
//! Every entry point returns the frames to put on the wire rather than sending
//! them, so the decision is testable without a link.

extern crate alloc;
use alloc::vec::Vec;

use super::chan::{Channel, TxFrame, CONN_REJ_ACT, CONN_REMOTE_BUSY, CONN_RNR_SENT, CONN_SEND_FBIT};
use super::ctrl::{next_seq, seq_offset, Ctrl};
use crate::uapi::l2cap as u;

/// Events the transmitter reacts to.
pub const EV_DATA_REQUEST: u8 = 0;
pub const EV_LOCAL_BUSY_DETECTED: u8 = 1;
pub const EV_LOCAL_BUSY_CLEAR: u8 = 2;
pub const EV_RECV_REQSEQ_AND_FBIT: u8 = 3;
pub const EV_RECV_FBIT: u8 = 4;
pub const EV_RETRANS_TO: u8 = 5;
pub const EV_MONITOR_TO: u8 = 6;
pub const EV_EXPLICIT_POLL: u8 = 7;

/// A frame to transmit: its control field and the bytes that follow it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutFrame {
    pub ctrl: Ctrl,
    pub body: Vec<u8>,
}

/// What the transmitter wants done.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxAction {
    Send(OutFrame),
    /// Arm the retransmission timer.
    SetRetransTimer,
    /// Disarm the retransmission timer.
    ClearRetransTimer,
    /// Arm the monitor timer.
    SetMonitorTimer,
    /// Disarm the monitor timer.
    ClearMonitorTimer,
    /// The peer has failed to acknowledge within the retry limit; tear the
    /// channel down.
    Disconnect,
}

/// Queue an SDU's segments for transmission. They are numbered as they go out,
/// not as they are queued, so a retransmission keeps its original number.
/// # C: O(n)
pub fn queue(chan: &mut Channel, frames: Vec<(u8, Vec<u8>)>) {
    for (sar, body) in frames {
        chan.tx_q.push(TxFrame { txseq: 0, sar, retries: 0, body });
    }
}

/// Send everything the window allows. Each frame acknowledges what has been
/// received, so a busy peer, a full window or a transmitter waiting for a final
/// bit all stop the loop. # C: O(n)
pub fn ertm_send(chan: &mut Channel) -> Vec<TxAction> {
    let mut acts = Vec::new();
    if !chan.can_send() { return acts; }
    if chan.cs(CONN_REMOTE_BUSY) { return acts; }
    while chan.tx_send_head < chan.tx_q.len()
        && chan.ertm.unacked_frames < chan.remote_tx_win
        && chan.ertm.tx_state == u::TX_STATE_XMIT
    {
        let txseq = chan.ertm.next_tx_seq;
        let reqseq = chan.ertm.buffer_seq;
        let final_ = chan.take_cs(CONN_SEND_FBIT);
        let idx = chan.tx_send_head;
        chan.tx_q[idx].txseq = txseq;
        chan.tx_q[idx].retries = 1;
        let sar = chan.tx_q[idx].sar;
        let body = chan.tx_q[idx].body.clone();
        chan.ertm.last_acked_seq = reqseq;
        chan.ertm.next_tx_seq = next_seq(chan.tx_win_max, txseq);
        chan.ertm.unacked_frames += 1;
        chan.ertm.frames_sent = chan.ertm.frames_sent.wrapping_add(1);
        chan.tx_send_head += 1;
        let mut c = Ctrl::iframe(txseq, sar, reqseq);
        c.final_ = final_;
        acts.push(TxAction::SetRetransTimer);
        acts.push(TxAction::Send(OutFrame { ctrl: c, body }));
    }
    acts
}

/// Retire frames the peer has acknowledged up to `reqseq`. # C: O(n)
pub fn process_reqseq(chan: &mut Channel, reqseq: u16) -> Vec<TxAction> {
    let mut acts = Vec::new();
    if chan.ertm.unacked_frames == 0 || reqseq == chan.ertm.expected_ack_seq { return acts; }
    let mut ackseq = chan.ertm.expected_ack_seq;
    while ackseq != reqseq {
        if let Some(pos) = chan.tx_q.iter().position(|f| f.txseq == ackseq && f.retries > 0) {
            chan.tx_q.remove(pos);
            if chan.tx_send_head > pos { chan.tx_send_head -= 1; }
            chan.ertm.unacked_frames -= 1;
        }
        ackseq = next_seq(chan.tx_win_max, ackseq);
    }
    chan.ertm.expected_ack_seq = reqseq;
    if chan.ertm.unacked_frames == 0 { acts.push(TxAction::ClearRetransTimer); }
    acts
}

/// Resend everything on the retransmission list. A frame that has already been
/// sent the permitted number of times ends the channel: retrying past the limit
/// is how a dead link is mistaken for a slow one forever. # C: O(n)
pub fn ertm_resend(chan: &mut Channel) -> Vec<TxAction> {
    let mut acts = Vec::new();
    if chan.cs(CONN_REMOTE_BUSY) { return acts; }
    while !chan.ertm.retrans_list.is_empty() {
        let seq = chan.ertm.retrans_list.remove(0);
        let Some(pos) = chan.tx_q.iter().position(|f| f.txseq == seq && f.retries > 0) else { continue };
        chan.tx_q[pos].retries = chan.tx_q[pos].retries.saturating_add(1);
        if chan.max_tx != 0 && chan.tx_q[pos].retries > chan.max_tx {
            chan.ertm.retrans_list.clear();
            acts.push(TxAction::Disconnect);
            return acts;
        }
        let final_ = chan.take_cs(CONN_SEND_FBIT);
        let mut c = Ctrl::iframe(seq, chan.tx_q[pos].sar, chan.ertm.buffer_seq);
        c.final_ = final_;
        chan.ertm.last_acked_seq = chan.ertm.buffer_seq;
        acts.push(TxAction::Send(OutFrame { ctrl: c, body: chan.tx_q[pos].body.clone() }));
    }
    acts
}

/// Queue one frame for retransmission and send it. # C: O(n)
pub fn retransmit(chan: &mut Channel, reqseq: u16) -> Vec<TxAction> {
    chan.ertm.retrans_list.push(reqseq);
    ertm_resend(chan)
}

/// Queue every unacknowledged frame from `reqseq` forward and send them all,
/// which is the answer to a reject. # C: O(n)
pub fn retransmit_all(chan: &mut Channel, ctrl: &Ctrl) -> Vec<TxAction> {
    if ctrl.poll { chan.set_cs(CONN_SEND_FBIT); }
    chan.ertm.retrans_list.clear();
    if chan.cs(CONN_REMOTE_BUSY) { return Vec::new(); }
    if chan.ertm.unacked_frames == 0 { return Vec::new(); }
    let start = chan.tx_q.iter().position(|f| f.txseq == ctrl.reqseq && f.retries > 0).unwrap_or(0);
    for i in start..chan.tx_send_head {
        let seq = chan.tx_q[i].txseq;
        chan.ertm.retrans_list.push(seq);
    }
    ertm_resend(chan)
}

/// A supervisory frame reporting whether this end can take more data. # C: O(1)
pub fn rr_or_rnr(chan: &mut Channel, poll: bool) -> OutFrame {
    let busy = chan.cs(super::chan::CONN_LOCAL_BUSY);
    let mut c = Ctrl::sframe(if busy { u::SUPER_RNR } else { u::SUPER_RR }, chan.ertm.buffer_seq);
    c.poll = poll;
    if busy { chan.set_cs(CONN_RNR_SENT); }
    if !poll && chan.take_cs(CONN_SEND_FBIT) { c.final_ = true; }
    chan.ertm.last_acked_seq = chan.ertm.buffer_seq;
    OutFrame { ctrl: c, body: Vec::new() }
}

/// How many received frames are waiting to be acknowledged. # C: O(1)
pub fn frames_to_ack(chan: &Channel) -> u16 {
    seq_offset(chan.tx_win_max, chan.ertm.buffer_seq, chan.ertm.last_acked_seq)
}

/// Whether enough frames have gone unacknowledged that one should be sent now
/// rather than waiting for the timer. The threshold is three quarters of the
/// window. # C: O(1)
pub fn ack_now(chan: &Channel) -> bool {
    let threshold = (chan.ack_win as u32 * 3) >> 2;
    frames_to_ack(chan) as u32 >= threshold
}

/// Drive the transmitter machine. # C: O(n)
pub fn tx_event(chan: &mut Channel, event: u8, ctrl: Option<&Ctrl>) -> Vec<TxAction> {
    match chan.ertm.tx_state {
        u::TX_STATE_XMIT => tx_state_xmit(chan, event, ctrl),
        u::TX_STATE_WAIT_F => tx_state_wait_f(chan, event, ctrl),
        _ => Vec::new(),
    }
}

/// The transmitting state: data goes out as the window allows, and a timeout or
/// an explicit poll moves to waiting for a final bit. # C: O(n)
fn tx_state_xmit(chan: &mut Channel, event: u8, ctrl: Option<&Ctrl>) -> Vec<TxAction> {
    let mut acts = Vec::new();
    match event {
        EV_DATA_REQUEST => acts.extend(ertm_send(chan)),
        EV_LOCAL_BUSY_DETECTED => { chan.set_cs(super::chan::CONN_LOCAL_BUSY); }
        EV_LOCAL_BUSY_CLEAR => {
            chan.clear_cs(super::chan::CONN_LOCAL_BUSY);
            if chan.cs(CONN_RNR_SENT) {
                let f = rr_or_rnr(chan, true);
                acts.push(TxAction::Send(f));
                chan.ertm.retry_count = 1;
                acts.push(TxAction::SetMonitorTimer);
                chan.ertm.tx_state = u::TX_STATE_WAIT_F;
            }
        }
        EV_RECV_REQSEQ_AND_FBIT => { if let Some(c) = ctrl { acts.extend(process_reqseq(chan, c.reqseq)); } }
        EV_EXPLICIT_POLL | EV_RETRANS_TO => {
            let f = rr_or_rnr(chan, true);
            acts.push(TxAction::Send(f));
            chan.ertm.retry_count = 1;
            acts.push(TxAction::SetMonitorTimer);
            chan.ertm.tx_state = u::TX_STATE_WAIT_F;
        }
        _ => {}
    }
    acts
}

/// Waiting for a final bit: data queues but does not go out, and the monitor
/// timer retries the poll up to the retry limit before giving up on the link.
/// # C: O(n)
fn tx_state_wait_f(chan: &mut Channel, event: u8, ctrl: Option<&Ctrl>) -> Vec<TxAction> {
    let mut acts = Vec::new();
    match event {
        EV_DATA_REQUEST => {}
        EV_LOCAL_BUSY_DETECTED => { chan.set_cs(super::chan::CONN_LOCAL_BUSY); }
        EV_LOCAL_BUSY_CLEAR => {
            chan.clear_cs(super::chan::CONN_LOCAL_BUSY);
            if chan.cs(CONN_RNR_SENT) {
                let f = rr_or_rnr(chan, true);
                acts.push(TxAction::Send(f));
                chan.ertm.retry_count = 1;
                acts.push(TxAction::SetMonitorTimer);
            }
        }
        EV_RECV_REQSEQ_AND_FBIT | EV_RECV_FBIT => {
            if event == EV_RECV_REQSEQ_AND_FBIT {
                if let Some(c) = ctrl { acts.extend(process_reqseq(chan, c.reqseq)); }
            }
            if ctrl.map(|c| c.final_).unwrap_or(false) {
                acts.push(TxAction::ClearMonitorTimer);
                if chan.ertm.unacked_frames > 0 { acts.push(TxAction::SetRetransTimer); }
                chan.ertm.retry_count = 0;
                chan.ertm.tx_state = u::TX_STATE_XMIT;
            }
        }
        EV_MONITOR_TO => {
            if chan.max_tx == 0 || chan.ertm.retry_count < chan.max_tx {
                let f = rr_or_rnr(chan, true);
                acts.push(TxAction::Send(f));
                acts.push(TxAction::SetMonitorTimer);
                chan.ertm.retry_count += 1;
            } else {
                acts.push(TxAction::Disconnect);
            }
        }
        _ => {}
    }
    acts
}

/// Answer a reject: everything from the rejected sequence forward goes again.
/// # C: O(n)
pub fn handle_rej(chan: &mut Channel, ctrl: &Ctrl) -> Vec<TxAction> {
    let mut acts = Vec::new();
    if !valid_reqseq(chan, ctrl.reqseq) { acts.push(TxAction::Disconnect); return acts; }
    chan.clear_cs(CONN_REMOTE_BUSY);
    acts.extend(process_reqseq(chan, ctrl.reqseq));
    if ctrl.final_ {
        if !chan.take_cs(CONN_REJ_ACT) { acts.extend(retransmit_all(chan, ctrl)); }
    } else {
        acts.extend(retransmit_all(chan, ctrl));
        acts.extend(ertm_send(chan));
        if chan.ertm.tx_state == u::TX_STATE_WAIT_F { chan.set_cs(CONN_REJ_ACT); }
    }
    acts
}

/// Answer a selective reject: only the named frame goes again, unless the peer
/// also polled, in which case the whole window does. # C: O(n)
pub fn handle_srej(chan: &mut Channel, ctrl: &Ctrl) -> Vec<TxAction> {
    let mut acts = Vec::new();
    if !valid_reqseq(chan, ctrl.reqseq) { acts.push(TxAction::Disconnect); return acts; }
    chan.clear_cs(CONN_REMOTE_BUSY);
    if ctrl.poll { acts.extend(retransmit_all(chan, ctrl)); }
    else { acts.extend(retransmit(chan, ctrl.reqseq)); }
    acts.extend(ertm_send(chan));
    acts
}

/// Answer a receiver-not-ready: hold transmission until the peer clears it.
/// # C: O(1)
pub fn handle_rnr(chan: &mut Channel, ctrl: &Ctrl) -> Vec<TxAction> {
    if !valid_reqseq(chan, ctrl.reqseq) { return [TxAction::Disconnect].to_vec(); }
    chan.set_cs(CONN_REMOTE_BUSY);
    process_reqseq(chan, ctrl.reqseq)
}

/// Whether an acknowledgement names a frame that could plausibly be
/// outstanding. One that does not is a protocol error rather than a stale
/// acknowledgement, because acting on it would retire frames never sent.
/// # C: O(1)
pub fn valid_reqseq(chan: &Channel, reqseq: u16) -> bool {
    let unacked = seq_offset(chan.tx_win_max, chan.ertm.next_tx_seq, chan.ertm.expected_ack_seq);
    seq_offset(chan.tx_win_max, chan.ertm.next_tx_seq, reqseq) <= unacked
}

#[cfg(test)]
#[path = "tests/ertm_tx.rs"]
mod tests;
