//! The retransmission receiver: classifying an arriving sequence number, and
//! the receive-side state machine that acts on the classification.
//!
//! Classification is the whole of the protocol's judgement about a frame — in
//! order, out of order, already seen, or outside the window entirely — so it is
//! a pure function of the channel's counters and is tested class by class.

extern crate alloc;
use alloc::vec::Vec;

use super::chan::{Channel, CONN_LOCAL_BUSY, CONN_REJ_ACT, CONN_REMOTE_BUSY, CONN_SEND_FBIT, CONN_SREJ_ACT};
use super::ctrl::{next_seq, seq_offset, Ctrl};
use super::ertm_tx::{ertm_send, process_reqseq, retransmit_all, rr_or_rnr, valid_reqseq, OutFrame, TxAction};
use super::sar::{reassemble, Reassembly};
use crate::uapi::l2cap as u;

/// Classification of an arriving sequence number.
pub const TXSEQ_EXPECTED: u8 = 0;
pub const TXSEQ_EXPECTED_SREJ: u8 = 1;
pub const TXSEQ_UNEXPECTED: u8 = 2;
pub const TXSEQ_UNEXPECTED_SREJ: u8 = 3;
pub const TXSEQ_DUPLICATE: u8 = 4;
pub const TXSEQ_DUPLICATE_SREJ: u8 = 5;
pub const TXSEQ_INVALID: u8 = 6;
pub const TXSEQ_INVALID_IGNORE: u8 = 7;

/// Receive-side events.
pub const EV_RECV_IFRAME: u8 = 0;
pub const EV_RECV_RR: u8 = 1;
pub const EV_RECV_REJ: u8 = 2;
pub const EV_RECV_RNR: u8 = 3;
pub const EV_RECV_SREJ: u8 = 4;

/// What the receiver wants done.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RxAction {
    /// A whole SDU is ready for the channel's owner.
    Deliver(Vec<u8>),
    Send(OutFrame),
    SetRetransTimer,
    ClearRetransTimer,
    SetMonitorTimer,
    ClearMonitorTimer,
    SetAckTimer,
    ClearAckTimer,
    /// The peer violated the protocol; tear the channel down.
    Disconnect,
}

/// Fold a transmitter action into the receiver's action list. # C: O(1)
fn from_tx(a: TxAction) -> RxAction {
    match a {
        TxAction::Send(f) => RxAction::Send(f),
        TxAction::SetRetransTimer => RxAction::SetRetransTimer,
        TxAction::ClearRetransTimer => RxAction::ClearRetransTimer,
        TxAction::SetMonitorTimer => RxAction::SetMonitorTimer,
        TxAction::ClearMonitorTimer => RxAction::ClearMonitorTimer,
        TxAction::Disconnect => RxAction::Disconnect,
    }
}

/// Extend `out` with transmitter actions. # C: O(n)
fn push_tx(out: &mut Vec<RxAction>, acts: Vec<TxAction>) { for a in acts { out.push(from_tx(a)); } }

/// Judge an arriving sequence number against the receive window.
///
/// Outside a selective-reject exchange the judgement is: the one expected, one
/// already consumed, one that leaves a gap, or one so far out that acting on it
/// would corrupt the window. That last case splits in two — a window no larger
/// than half the sequence space cannot produce a false gap from a repeated
/// poll, so such a frame is ignorable; a larger window cannot tell the two
/// apart and the channel must go down. # C: O(n)
pub fn classify_txseq(chan: &Channel, txseq: u16) -> u8 {
    let e = &chan.ertm;
    let win = chan.tx_win;
    let half = (chan.tx_win_max + 1) >> 1;

    if e.rx_state == u::RX_STATE_SREJ_SENT {
        if seq_offset(chan.tx_win_max, txseq, e.last_acked_seq) >= win {
            return if win <= half { TXSEQ_INVALID_IGNORE } else { TXSEQ_INVALID };
        }
        if e.srej_list.first() == Some(&txseq) { return TXSEQ_EXPECTED_SREJ; }
        if e.srej_q.contains(&txseq) { return TXSEQ_DUPLICATE_SREJ; }
        if e.srej_list.contains(&txseq) { return TXSEQ_UNEXPECTED_SREJ; }
    }

    if e.expected_tx_seq == txseq {
        return if seq_offset(chan.tx_win_max, txseq, e.last_acked_seq) >= win { TXSEQ_INVALID } else { TXSEQ_EXPECTED };
    }

    if seq_offset(chan.tx_win_max, txseq, e.last_acked_seq)
        < seq_offset(chan.tx_win_max, e.expected_tx_seq, e.last_acked_seq)
    {
        return TXSEQ_DUPLICATE;
    }

    if seq_offset(chan.tx_win_max, txseq, e.last_acked_seq) >= win {
        return if win <= half { TXSEQ_INVALID_IGNORE } else { TXSEQ_INVALID };
    }

    TXSEQ_UNEXPECTED
}

/// A selective reject naming one missing frame. # C: O(1)
fn srej_frame(chan: &mut Channel, txseq: u16) -> OutFrame {
    chan.ertm.srej_list.push(txseq);
    let mut c = Ctrl::sframe(u::SUPER_SREJ, txseq);
    if chan.take_cs(CONN_SEND_FBIT) { c.final_ = true; }
    OutFrame { ctrl: c, body: Vec::new() }
}

/// Acknowledge what has been received, either now or on the timer. # C: O(n)
fn send_ack(chan: &mut Channel) -> Vec<RxAction> {
    let mut out = Vec::new();
    if chan.cs(CONN_LOCAL_BUSY) && chan.ertm.rx_state == u::RX_STATE_RECV {
        out.push(RxAction::ClearAckTimer);
        let f = rr_or_rnr(chan, false);
        out.push(RxAction::Send(f));
        return out;
    }
    if !chan.cs(CONN_REMOTE_BUSY) { push_tx(&mut out, ertm_send(chan)); }
    if super::ertm_tx::ack_now(chan) {
        out.push(RxAction::ClearAckTimer);
        let f = rr_or_rnr(chan, false);
        out.push(RxAction::Send(f));
    } else if super::ertm_tx::frames_to_ack(chan) > 0 {
        out.push(RxAction::SetAckTimer);
    }
    out
}

/// Drive the receiver. A frame acknowledging something never sent is a
/// protocol error and is refused before any state changes. # C: O(n)
pub fn rx(chan: &mut Channel, ctrl: &Ctrl, data: &[u8], event: u8) -> Vec<RxAction> {
    if !valid_reqseq(chan, ctrl.reqseq) { return [RxAction::Disconnect].to_vec(); }
    match chan.ertm.rx_state {
        u::RX_STATE_RECV => rx_state_recv(chan, ctrl, data, event),
        u::RX_STATE_SREJ_SENT => rx_state_srej_sent(chan, ctrl, data, event),
        u::RX_STATE_WAIT_P => rx_state_wait_p(chan, ctrl, event),
        u::RX_STATE_WAIT_F => rx_state_wait_f(chan, ctrl, event),
        _ => Vec::new(),
    }
}

/// The in-order state: frames are consumed as they arrive, and the first gap
/// starts a selective-reject exchange. # C: O(n)
fn rx_state_recv(chan: &mut Channel, ctrl: &Ctrl, data: &[u8], event: u8) -> Vec<RxAction> {
    let mut out = Vec::new();
    match event {
        EV_RECV_IFRAME => match classify_txseq(chan, ctrl.txseq) {
            TXSEQ_EXPECTED => {
                push_tx(&mut out, process_reqseq(chan, ctrl.reqseq));
                if chan.cs(CONN_LOCAL_BUSY) { return out; }
                chan.ertm.expected_tx_seq = next_seq(chan.tx_win_max, ctrl.txseq);
                chan.ertm.buffer_seq = chan.ertm.expected_tx_seq;
                match reassemble(chan, ctrl.sar, data) {
                    Reassembly::Complete(sdu) => out.push(RxAction::Deliver(sdu)),
                    Reassembly::Incomplete => {}
                    Reassembly::Error => return out,
                }
                if ctrl.final_ && !chan.take_cs(CONN_REJ_ACT) {
                    let mut c = *ctrl;
                    c.final_ = false;
                    push_tx(&mut out, retransmit_all(chan, &c));
                    push_tx(&mut out, ertm_send(chan));
                }
                if !chan.cs(CONN_LOCAL_BUSY) { out.extend(send_ack(chan)); }
            }
            TXSEQ_UNEXPECTED => {
                push_tx(&mut out, process_reqseq(chan, ctrl.reqseq));
                if chan.cs(CONN_LOCAL_BUSY) { return out; }
                chan.ertm.srej_q.push(ctrl.txseq);
                chan.clear_cs(CONN_SREJ_ACT);
                chan.ertm.srej_list.clear();
                let f = srej_frame(chan, chan.ertm.expected_tx_seq);
                out.push(RxAction::Send(f));
                chan.ertm.rx_state = u::RX_STATE_SREJ_SENT;
            }
            TXSEQ_DUPLICATE => { push_tx(&mut out, process_reqseq(chan, ctrl.reqseq)); }
            TXSEQ_INVALID_IGNORE => {}
            _ => out.push(RxAction::Disconnect),
        },
        EV_RECV_RR => {
            push_tx(&mut out, process_reqseq(chan, ctrl.reqseq));
            if ctrl.final_ {
                chan.clear_cs(CONN_REMOTE_BUSY);
                if !chan.take_cs(CONN_REJ_ACT) {
                    let mut c = *ctrl;
                    c.final_ = false;
                    push_tx(&mut out, retransmit_all(chan, &c));
                }
                push_tx(&mut out, ertm_send(chan));
            } else if ctrl.poll {
                let f = rr_or_rnr(chan, false);
                out.push(RxAction::Send(f));
            } else {
                if chan.take_cs(CONN_REMOTE_BUSY) && chan.ertm.unacked_frames > 0 {
                    out.push(RxAction::SetRetransTimer);
                }
                push_tx(&mut out, ertm_send(chan));
            }
        }
        EV_RECV_RNR => {
            chan.set_cs(CONN_REMOTE_BUSY);
            push_tx(&mut out, process_reqseq(chan, ctrl.reqseq));
            if ctrl.poll {
                chan.set_cs(CONN_SEND_FBIT);
                let f = rr_or_rnr(chan, false);
                out.push(RxAction::Send(f));
            }
            out.push(RxAction::ClearRetransTimer);
            chan.ertm.retrans_list.clear();
        }
        EV_RECV_REJ => push_tx(&mut out, super::ertm_tx::handle_rej(chan, ctrl)),
        EV_RECV_SREJ => push_tx(&mut out, super::ertm_tx::handle_srej(chan, ctrl)),
        _ => {}
    }
    out
}

/// The gap-filling state: the frames named by outstanding selective rejects are
/// taken in order, everything past the gap is held, and the state ends when the
/// gap closes. # C: O(n)
fn rx_state_srej_sent(chan: &mut Channel, ctrl: &Ctrl, data: &[u8], event: u8) -> Vec<RxAction> {
    let mut out = Vec::new();
    if event != EV_RECV_IFRAME {
        return match event {
            EV_RECV_RR | EV_RECV_RNR => { push_tx(&mut out, process_reqseq(chan, ctrl.reqseq)); out }
            EV_RECV_REJ => { push_tx(&mut out, super::ertm_tx::handle_rej(chan, ctrl)); out }
            EV_RECV_SREJ => { push_tx(&mut out, super::ertm_tx::handle_srej(chan, ctrl)); out }
            _ => out,
        };
    }

    match classify_txseq(chan, ctrl.txseq) {
        TXSEQ_EXPECTED => {
            // A frame arriving in order while a gap is outstanding is held
            // behind the gap, never delivered ahead of it.
            chan.ertm.srej_list.clear();
            chan.ertm.srej_q.push(ctrl.txseq);
            let f = srej_frame(chan, ctrl.txseq);
            out.push(RxAction::Send(f));
        }
        TXSEQ_EXPECTED_SREJ => {
            if !chan.ertm.srej_list.is_empty() { chan.ertm.srej_list.remove(0); }
            match reassemble(chan, ctrl.sar, data) {
                Reassembly::Complete(sdu) => out.push(RxAction::Deliver(sdu)),
                Reassembly::Incomplete => {}
                Reassembly::Error => return out,
            }
            chan.ertm.buffer_seq = next_seq(chan.tx_win_max, chan.ertm.buffer_seq);
            if chan.ertm.srej_list.is_empty() {
                chan.ertm.rx_state = u::RX_STATE_RECV;
                out.extend(deliver_queued(chan));
                out.extend(send_ack(chan));
            }
        }
        TXSEQ_UNEXPECTED => {
            let missing = chan.ertm.expected_tx_seq;
            let mut seq = missing;
            while seq != ctrl.txseq {
                let f = srej_frame(chan, seq);
                out.push(RxAction::Send(f));
                seq = next_seq(chan.tx_win_max, seq);
            }
            chan.ertm.srej_q.push(ctrl.txseq);
            chan.ertm.expected_tx_seq = next_seq(chan.tx_win_max, ctrl.txseq);
        }
        TXSEQ_UNEXPECTED_SREJ | TXSEQ_DUPLICATE_SREJ | TXSEQ_DUPLICATE => {}
        TXSEQ_INVALID_IGNORE => {}
        _ => out.push(RxAction::Disconnect),
    }
    out
}

/// Release the frames held behind a closed gap. # C: O(n)
fn deliver_queued(chan: &mut Channel) -> Vec<RxAction> {
    let mut out = Vec::new();
    let held = core::mem::take(&mut chan.ertm.srej_q);
    for seq in held {
        chan.ertm.expected_tx_seq = next_seq(chan.tx_win_max, seq);
        chan.ertm.buffer_seq = chan.ertm.expected_tx_seq;
    }
    out.push(RxAction::ClearAckTimer);
    out
}

/// Waiting for a poll to be answered: only the answer moves the state on.
/// # C: O(n)
fn rx_state_wait_p(chan: &mut Channel, ctrl: &Ctrl, event: u8) -> Vec<RxAction> {
    let mut out = Vec::new();
    if event == EV_RECV_IFRAME || !ctrl.final_ { return out; }
    chan.ertm.rx_state = u::RX_STATE_RECV;
    push_tx(&mut out, process_reqseq(chan, ctrl.reqseq));
    out
}

/// Waiting for a final bit: the answer restores in-order reception. # C: O(n)
fn rx_state_wait_f(chan: &mut Channel, ctrl: &Ctrl, event: u8) -> Vec<RxAction> {
    let mut out = Vec::new();
    if event == EV_RECV_IFRAME { return out; }
    if ctrl.final_ {
        chan.clear_cs(CONN_REMOTE_BUSY);
        chan.ertm.rx_state = u::RX_STATE_RECV;
        push_tx(&mut out, process_reqseq(chan, ctrl.reqseq));
        push_tx(&mut out, ertm_send(chan));
    }
    out
}

/// The event a received supervisory frame stands for. # C: O(1)
pub fn sframe_event(super_: u8) -> u8 {
    match super_ {
        u::SUPER_RR => EV_RECV_RR,
        u::SUPER_REJ => EV_RECV_REJ,
        u::SUPER_RNR => EV_RECV_RNR,
        _ => EV_RECV_SREJ,
    }
}

#[cfg(test)]
#[path = "tests/ertm_rx.rs"]
mod tests;
