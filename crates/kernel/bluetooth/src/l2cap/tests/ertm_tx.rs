//! The transmitter: the window bounds what goes out, acknowledgement retires
//! frames, a reject resends them, and the retry limit ends the channel rather
//! than resending forever.

use super::*;
use crate::uapi::bt::BT_CONNECTED;
use alloc::vec;

fn ertm_chan(window: u16) -> Channel {
    let mut c = Channel::new();
    c.state = BT_CONNECTED;
    c.mode = u::MODE_ERTM;
    c.remote_tx_win = window;
    c.ertm_init();
    c
}

fn sent(acts: &[TxAction]) -> alloc::vec::Vec<Ctrl> {
    acts.iter().filter_map(|a| match a { TxAction::Send(f) => Some(f.ctrl), _ => None }).collect()
}

fn queue_n(chan: &mut Channel, n: usize) {
    let frames = (0..n).map(|i| (u::SAR_UNSEGMENTED, vec![i as u8])).collect();
    queue(chan, frames);
}

#[test]
fn the_window_bounds_how_many_frames_go_out() {
    let mut c = ertm_chan(2);
    queue_n(&mut c, 5);
    let acts = ertm_send(&mut c);
    let out = sent(&acts);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].txseq, 0);
    assert_eq!(out[1].txseq, 1);
    assert_eq!(c.ertm.unacked_frames, 2);
    assert_eq!(c.tx_send_head, 2);
    // The rest stay queued.
    assert!(sent(&ertm_send(&mut c)).is_empty());
}

#[test]
fn every_frame_carries_the_sequence_the_receiver_is_waiting_for() {
    let mut c = ertm_chan(4);
    c.ertm.buffer_seq = 7;
    queue_n(&mut c, 1);
    let out = sent(&ertm_send(&mut c));
    assert_eq!(out[0].reqseq, 7);
    assert_eq!(c.ertm.last_acked_seq, 7);
}

#[test]
fn a_channel_that_is_not_open_sends_nothing() {
    let mut c = ertm_chan(4);
    c.state = crate::uapi::bt::BT_CONFIG;
    queue_n(&mut c, 2);
    assert!(sent(&ertm_send(&mut c)).is_empty());
}

#[test]
fn a_busy_peer_stops_transmission() {
    let mut c = ertm_chan(4);
    c.set_cs(CONN_REMOTE_BUSY);
    queue_n(&mut c, 2);
    assert!(sent(&ertm_send(&mut c)).is_empty());
}

#[test]
fn acknowledgement_retires_the_frames_it_covers() {
    let mut c = ertm_chan(4);
    queue_n(&mut c, 3);
    ertm_send(&mut c);
    assert_eq!(c.ertm.unacked_frames, 3);
    let acts = process_reqseq(&mut c, 2);
    assert_eq!(c.ertm.unacked_frames, 1);
    assert_eq!(c.ertm.expected_ack_seq, 2);
    assert!(!acts.contains(&TxAction::ClearRetransTimer));
    process_reqseq(&mut c, 3);
    assert_eq!(c.ertm.unacked_frames, 0);
    assert!(process_reqseq(&mut c, 3).is_empty());
}

#[test]
fn retiring_the_last_frame_disarms_the_retransmission_timer() {
    let mut c = ertm_chan(4);
    queue_n(&mut c, 2);
    ertm_send(&mut c);
    let acts = process_reqseq(&mut c, 2);
    assert!(acts.contains(&TxAction::ClearRetransTimer));
}

#[test]
fn a_reject_resends_everything_from_the_rejected_sequence() {
    let mut c = ertm_chan(4);
    queue_n(&mut c, 3);
    ertm_send(&mut c);
    let ctrl = Ctrl::sframe(u::SUPER_REJ, 1);
    let out = sent(&handle_rej(&mut c, &ctrl));
    let seqs: alloc::vec::Vec<u16> = out.iter().filter(|c| !c.sframe).map(|c| c.txseq).collect();
    assert_eq!(seqs, vec![1, 2]);
}

#[test]
fn a_selective_reject_resends_only_the_frame_it_names() {
    let mut c = ertm_chan(4);
    queue_n(&mut c, 3);
    ertm_send(&mut c);
    let ctrl = Ctrl::sframe(u::SUPER_SREJ, 1);
    let out = sent(&handle_srej(&mut c, &ctrl));
    let seqs: alloc::vec::Vec<u16> = out.iter().filter(|c| !c.sframe).map(|c| c.txseq).collect();
    assert_eq!(seqs, vec![1]);
}

#[test]
fn exhausting_the_retry_limit_ends_the_channel() {
    let mut c = ertm_chan(4);
    c.max_tx = 3;
    queue_n(&mut c, 1);
    ertm_send(&mut c);
    // The first transmission counts as one; the limit allows two more.
    for round in 0..2 {
        let acts = retransmit(&mut c, 0);
        assert!(!acts.contains(&TxAction::Disconnect), "round {round} should still retry");
        assert!(!sent(&acts).is_empty());
    }
    let acts = retransmit(&mut c, 0);
    assert!(acts.contains(&TxAction::Disconnect));
    assert!(sent(&acts).is_empty());
    assert!(c.ertm.retrans_list.is_empty());
}

#[test]
fn a_retry_limit_of_zero_never_gives_up() {
    let mut c = ertm_chan(4);
    c.max_tx = 0;
    queue_n(&mut c, 1);
    ertm_send(&mut c);
    for _ in 0..10 {
        let acts = retransmit(&mut c, 0);
        assert!(!acts.contains(&TxAction::Disconnect));
    }
}

#[test]
fn an_acknowledgement_of_a_frame_never_sent_is_a_protocol_error() {
    let mut c = ertm_chan(4);
    queue_n(&mut c, 2);
    ertm_send(&mut c);
    assert!(valid_reqseq(&c, 0));
    assert!(valid_reqseq(&c, 2));
    assert!(!valid_reqseq(&c, 3));
    assert!(handle_rej(&mut c, &Ctrl::sframe(u::SUPER_REJ, 3)).contains(&TxAction::Disconnect));
}

#[test]
fn a_receiver_not_ready_holds_transmission_until_it_is_cleared() {
    let mut c = ertm_chan(4);
    queue_n(&mut c, 2);
    ertm_send(&mut c);
    handle_rnr(&mut c, &Ctrl::sframe(u::SUPER_RNR, 0));
    assert!(c.cs(CONN_REMOTE_BUSY));
    queue_n(&mut c, 1);
    assert!(sent(&ertm_send(&mut c)).is_empty());
}

#[test]
fn a_poll_moves_the_transmitter_to_waiting_for_a_final_bit() {
    let mut c = ertm_chan(4);
    let acts = tx_event(&mut c, EV_EXPLICIT_POLL, None);
    assert_eq!(c.ertm.tx_state, u::TX_STATE_WAIT_F);
    assert_eq!(c.ertm.retry_count, 1);
    assert!(acts.contains(&TxAction::SetMonitorTimer));
    let out = sent(&acts);
    assert!(out[0].sframe && out[0].poll);
    // Data queues but does not go out while waiting.
    queue_n(&mut c, 1);
    assert!(sent(&tx_event(&mut c, EV_DATA_REQUEST, None)).is_empty());
}

#[test]
fn a_final_bit_returns_the_transmitter_to_sending() {
    let mut c = ertm_chan(4);
    tx_event(&mut c, EV_EXPLICIT_POLL, None);
    let mut ctrl = Ctrl::sframe(u::SUPER_RR, 0);
    ctrl.final_ = true;
    let acts = tx_event(&mut c, EV_RECV_FBIT, Some(&ctrl));
    assert_eq!(c.ertm.tx_state, u::TX_STATE_XMIT);
    assert_eq!(c.ertm.retry_count, 0);
    assert!(acts.contains(&TxAction::ClearMonitorTimer));
}

#[test]
fn the_monitor_timer_retries_the_poll_and_then_gives_up() {
    let mut c = ertm_chan(4);
    c.max_tx = 2;
    tx_event(&mut c, EV_EXPLICIT_POLL, None);
    let acts = tx_event(&mut c, EV_MONITOR_TO, None);
    assert!(!acts.contains(&TxAction::Disconnect));
    assert_eq!(c.ertm.retry_count, 2);
    let acts = tx_event(&mut c, EV_MONITOR_TO, None);
    assert!(acts.contains(&TxAction::Disconnect));
}

#[test]
fn an_acknowledgement_is_sent_once_the_window_is_three_quarters_unacknowledged() {
    let mut c = ertm_chan(4);
    c.ack_win = 4;
    c.ertm.buffer_seq = 2;
    c.ertm.last_acked_seq = 0;
    assert_eq!(frames_to_ack(&c), 2);
    assert!(!ack_now(&c));
    c.ertm.buffer_seq = 3;
    assert!(ack_now(&c));
}

#[test]
fn the_supervisory_frame_reports_whether_this_end_can_take_more() {
    let mut c = ertm_chan(4);
    assert_eq!(rr_or_rnr(&mut c, false).ctrl.super_, u::SUPER_RR);
    c.set_cs(super::super::chan::CONN_LOCAL_BUSY);
    let f = rr_or_rnr(&mut c, true);
    assert_eq!(f.ctrl.super_, u::SUPER_RNR);
    assert!(f.ctrl.poll);
    assert!(c.cs(CONN_RNR_SENT));
}
