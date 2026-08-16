//! Sequence classification — all eight verdicts — and the receiver states that
//! act on them.

use super::*;
use crate::uapi::bt::BT_CONNECTED;
use alloc::vec;

fn rx_chan(tx_win: u16) -> Channel {
    let mut c = Channel::new();
    c.state = BT_CONNECTED;
    c.mode = u::MODE_ERTM;
    c.tx_win = tx_win;
    c.tx_win_max = u::DEFAULT_TX_WINDOW;
    c.ertm_init();
    c
}

#[test]
fn the_sequence_the_receiver_is_waiting_for_is_expected() {
    let c = rx_chan(8);
    assert_eq!(classify_txseq(&c, 0), TXSEQ_EXPECTED);
}

#[test]
fn a_sequence_already_consumed_is_a_duplicate() {
    let mut c = rx_chan(8);
    c.ertm.expected_tx_seq = 3;
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 1), TXSEQ_DUPLICATE);
}

#[test]
fn a_sequence_leaving_a_gap_is_unexpected() {
    let mut c = rx_chan(8);
    c.ertm.expected_tx_seq = 2;
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 4), TXSEQ_UNEXPECTED);
}

#[test]
fn a_sequence_outside_a_narrow_window_can_be_ignored() {
    // A window no larger than half the sequence space cannot produce a false
    // gap, so an out-of-window frame is safely ignorable.
    let mut c = rx_chan(8);
    c.ertm.expected_tx_seq = 1;
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 40), TXSEQ_INVALID_IGNORE);
}

#[test]
fn a_sequence_outside_a_wide_window_ends_the_channel() {
    let mut c = rx_chan(u::DEFAULT_TX_WINDOW);
    c.ertm.expected_tx_seq = 1;
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 63), TXSEQ_INVALID);
}

#[test]
fn the_expected_sequence_outside_the_window_is_invalid_rather_than_expected() {
    let mut c = rx_chan(4);
    c.ertm.last_acked_seq = 0;
    c.ertm.expected_tx_seq = 8;
    assert_eq!(classify_txseq(&c, 8), TXSEQ_INVALID);
}

#[test]
fn during_a_gap_the_head_of_the_outstanding_list_is_the_expected_one() {
    let mut c = rx_chan(8);
    c.ertm.rx_state = u::RX_STATE_SREJ_SENT;
    c.ertm.srej_list = vec![2, 3];
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 2), TXSEQ_EXPECTED_SREJ);
    assert_eq!(classify_txseq(&c, 3), TXSEQ_UNEXPECTED_SREJ);
}

#[test]
fn during_a_gap_a_frame_already_held_is_a_duplicate() {
    let mut c = rx_chan(8);
    c.ertm.rx_state = u::RX_STATE_SREJ_SENT;
    c.ertm.srej_list = vec![2];
    c.ertm.srej_q = vec![5];
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 5), TXSEQ_DUPLICATE_SREJ);
}

#[test]
fn during_a_gap_a_frame_outside_the_window_follows_the_same_split() {
    let mut c = rx_chan(4);
    c.ertm.rx_state = u::RX_STATE_SREJ_SENT;
    c.ertm.srej_list = vec![2];
    c.ertm.last_acked_seq = 0;
    assert_eq!(classify_txseq(&c, 20), TXSEQ_INVALID_IGNORE);
    // A window past half the sequence space cannot tell a repeated poll from
    // new data, so the same frame ends the channel instead.
    c.tx_win = 40;
    assert_eq!(classify_txseq(&c, 50), TXSEQ_INVALID);
}

#[test]
fn all_eight_verdicts_are_reachable() {
    let mut seen = alloc::vec::Vec::new();
    // in order
    let c = rx_chan(8);
    seen.push(classify_txseq(&c, 0));
    // already consumed
    let mut c2 = rx_chan(8);
    c2.ertm.expected_tx_seq = 3;
    seen.push(classify_txseq(&c2, 1));
    // gap
    seen.push(classify_txseq(&c2, 5));
    // out of a narrow window
    seen.push(classify_txseq(&c2, 40));
    // out of a wide window
    let mut c3 = rx_chan(u::DEFAULT_TX_WINDOW);
    c3.ertm.expected_tx_seq = 1;
    seen.push(classify_txseq(&c3, 63));
    // the three gap-state verdicts
    let mut c4 = rx_chan(8);
    c4.ertm.rx_state = u::RX_STATE_SREJ_SENT;
    c4.ertm.srej_list = vec![2, 3];
    c4.ertm.srej_q = vec![6];
    seen.push(classify_txseq(&c4, 2));
    seen.push(classify_txseq(&c4, 3));
    seen.push(classify_txseq(&c4, 6));
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 8, "every verdict must be reachable, saw {seen:?}");
}

#[test]
fn an_in_order_frame_is_delivered_and_advances_the_receiver() {
    let mut c = rx_chan(8);
    let ctrl = Ctrl::iframe(0, u::SAR_UNSEGMENTED, 0);
    let acts = rx(&mut c, &ctrl, &[7, 7], EV_RECV_IFRAME);
    assert!(acts.iter().any(|a| matches!(a, RxAction::Deliver(v) if v == &vec![7, 7])));
    assert_eq!(c.ertm.expected_tx_seq, 1);
    assert_eq!(c.ertm.buffer_seq, 1);
}

#[test]
fn a_gap_starts_a_selective_reject_exchange() {
    let mut c = rx_chan(8);
    let ctrl = Ctrl::iframe(2, u::SAR_UNSEGMENTED, 0);
    let acts = rx(&mut c, &ctrl, &[1], EV_RECV_IFRAME);
    assert_eq!(c.ertm.rx_state, u::RX_STATE_SREJ_SENT);
    let srej = acts.iter().find_map(|a| match a { RxAction::Send(f) if f.ctrl.sframe => Some(f.ctrl), _ => None });
    let srej = srej.expect("a selective reject goes out");
    assert_eq!(srej.super_, u::SUPER_SREJ);
    assert_eq!(srej.reqseq, 0);
    assert!(c.ertm.srej_q.contains(&2));
}

#[test]
fn a_frame_outside_a_wide_window_ends_the_channel() {
    let mut c = rx_chan(u::DEFAULT_TX_WINDOW);
    c.ertm.expected_tx_seq = 1;
    let ctrl = Ctrl::iframe(63, u::SAR_UNSEGMENTED, 0);
    assert!(rx(&mut c, &ctrl, &[], EV_RECV_IFRAME).contains(&RxAction::Disconnect));
}

#[test]
fn a_frame_acknowledging_something_never_sent_ends_the_channel() {
    let mut c = rx_chan(8);
    let ctrl = Ctrl::iframe(0, u::SAR_UNSEGMENTED, 9);
    assert_eq!(rx(&mut c, &ctrl, &[], EV_RECV_IFRAME), vec![RxAction::Disconnect]);
}

#[test]
fn a_busy_receiver_discards_rather_than_delivering() {
    let mut c = rx_chan(8);
    c.set_cs(super::super::chan::CONN_LOCAL_BUSY);
    let ctrl = Ctrl::iframe(0, u::SAR_UNSEGMENTED, 0);
    let acts = rx(&mut c, &ctrl, &[1], EV_RECV_IFRAME);
    assert!(!acts.iter().any(|a| matches!(a, RxAction::Deliver(_))));
    assert_eq!(c.ertm.expected_tx_seq, 0);
}

#[test]
fn a_receiver_not_ready_records_the_peer_as_busy() {
    let mut c = rx_chan(8);
    let ctrl = Ctrl::sframe(u::SUPER_RNR, 0);
    let acts = rx(&mut c, &ctrl, &[], EV_RECV_RNR);
    assert!(c.cs(CONN_REMOTE_BUSY));
    assert!(acts.contains(&RxAction::ClearRetransTimer));
}

#[test]
fn the_supervisory_function_maps_to_the_event_it_stands_for() {
    assert_eq!(sframe_event(u::SUPER_RR), EV_RECV_RR);
    assert_eq!(sframe_event(u::SUPER_REJ), EV_RECV_REJ);
    assert_eq!(sframe_event(u::SUPER_RNR), EV_RECV_RNR);
    assert_eq!(sframe_event(u::SUPER_SREJ), EV_RECV_SREJ);
}

#[test]
fn filling_the_gap_returns_the_receiver_to_taking_frames_in_order() {
    let mut c = rx_chan(8);
    // A gap opens.
    rx(&mut c, &Ctrl::iframe(2, u::SAR_UNSEGMENTED, 0), &[9], EV_RECV_IFRAME);
    assert_eq!(c.ertm.rx_state, u::RX_STATE_SREJ_SENT);
    // The missing frame arrives.
    let acts = rx(&mut c, &Ctrl::iframe(0, u::SAR_UNSEGMENTED, 0), &[1], EV_RECV_IFRAME);
    assert!(acts.iter().any(|a| matches!(a, RxAction::Deliver(v) if v == &vec![1])));
    assert_eq!(c.ertm.rx_state, u::RX_STATE_RECV);
}
