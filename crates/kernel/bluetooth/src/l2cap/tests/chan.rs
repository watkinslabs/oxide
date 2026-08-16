//! Channel state: the bit sets, the window setup, and the state transitions
//! that must not happen.

use super::*;
use crate::uapi::bt::{BT_CLOSED, BT_CONFIG, BT_CONNECT2, BT_CONNECTED, BT_LISTEN, BT_OPEN};

#[test]
fn a_new_channel_starts_incomplete_and_at_the_protocol_defaults() {
    let c = Channel::new();
    assert_eq!(c.state, BT_OPEN);
    assert!(c.conf(CONF_NOT_COMPLETE));
    assert!(!c.conf_complete());
    assert_eq!(c.tx_win, u::DEFAULT_TX_WINDOW);
    assert_eq!(c.max_tx, u::DEFAULT_MAX_TX);
    assert_eq!(c.retrans_timeout, u::DEFAULT_RETRANS_TO);
    assert_eq!(c.monitor_timeout, u::DEFAULT_MONITOR_TO);
    assert_eq!(c.flush_to, u::DEFAULT_FLUSH_TO);
    assert_eq!(c.sec_level, crate::uapi::bt::BT_SECURITY_LOW);
}

#[test]
fn the_three_bit_sets_are_independent() {
    let mut c = Channel::new();
    c.set_conf(CONF_MTU_DONE);
    c.set_cs(CONN_LOCAL_BUSY);
    c.set_flag(FLAG_EXT_CTRL);
    assert!(c.conf(CONF_MTU_DONE) && c.cs(CONN_LOCAL_BUSY) && c.flag(FLAG_EXT_CTRL));
    assert!(!c.conf(CONF_MODE_DONE) && !c.cs(CONN_REMOTE_BUSY) && !c.flag(FLAG_DEFER_SETUP));
    c.clear_conf(CONF_MTU_DONE);
    assert!(!c.conf(CONF_MTU_DONE));
    assert!(c.take_cs(CONN_LOCAL_BUSY));
    assert!(!c.take_cs(CONN_LOCAL_BUSY));
}

#[test]
fn both_directions_must_settle_before_the_channel_is_configured() {
    let mut c = Channel::new();
    c.set_conf(CONF_INPUT_DONE);
    assert!(!c.conf_complete());
    c.set_conf(CONF_OUTPUT_DONE);
    assert!(c.conf_complete());
}

#[test]
fn a_closed_channel_cannot_be_reopened_in_place() {
    let mut c = Channel::new();
    assert!(c.set_state(BT_CONNECTED));
    assert!(c.set_state(BT_CLOSED));
    assert!(!c.set_state(BT_CONNECTED));
    assert_eq!(c.state, BT_CLOSED);
    assert!(c.set_state(BT_CLOSED));
}

#[test]
fn configuration_is_allowed_only_in_the_states_that_can_use_it() {
    let mut c = Channel::new();
    for s in [BT_CONFIG, BT_CONNECT2, BT_CONNECTED] { c.state = s; assert!(c.conf_allowed()); }
    for s in [BT_OPEN, BT_LISTEN, BT_CLOSED] { c.state = s; assert!(!c.conf_allowed()); }
}

#[test]
fn a_window_past_the_basic_field_needs_the_extended_one() {
    let mut c = Channel::new();
    c.tx_win = 200;
    c.txwin_setup(true);
    assert!(c.flag(FLAG_EXT_CTRL));
    assert_eq!(c.tx_win_max, u::DEFAULT_EXT_WINDOW);
    assert_eq!(c.ack_win, 200);
}

#[test]
fn without_peer_support_the_window_is_clamped_to_the_basic_field() {
    let mut c = Channel::new();
    c.tx_win = 200;
    c.txwin_setup(false);
    assert!(!c.flag(FLAG_EXT_CTRL));
    assert_eq!(c.tx_win, u::DEFAULT_TX_WINDOW);
    assert_eq!(c.tx_win_max, u::DEFAULT_TX_WINDOW);
}

#[test]
fn the_frame_check_sequence_applies_only_to_the_sequence_numbered_modes() {
    let mut c = Channel::new();
    c.mode = u::MODE_BASIC;
    assert_eq!(c.default_fcs(), u::FCS_NONE);
    c.mode = u::MODE_ERTM;
    assert_eq!(c.default_fcs(), u::FCS_CRC16);
    c.set_conf(CONF_RECV_NO_FCS);
    c.fcs = u::FCS_NONE;
    assert_eq!(c.default_fcs(), u::FCS_NONE);
}

#[test]
fn the_credit_modes_are_recognised_as_one_family() {
    let mut c = Channel::new();
    c.mode = u::MODE_LE_FLOWCTL;
    assert!(c.is_credit_mode());
    c.mode = u::MODE_EXT_FLOWCTL;
    assert!(c.is_credit_mode());
    c.mode = u::MODE_ERTM;
    assert!(!c.is_credit_mode() && c.is_ertm());
}

#[test]
fn initialising_the_retransmission_state_clears_the_queue() {
    let mut c = Channel::new();
    c.tx_q.push(TxFrame { txseq: 3, sar: 0, retries: 2, body: alloc::vec::Vec::new() });
    c.tx_send_head = 1;
    c.ertm.next_tx_seq = 9;
    c.ertm_init();
    assert!(c.tx_q.is_empty());
    assert_eq!(c.tx_send_head, 0);
    assert_eq!(c.ertm.next_tx_seq, 0);
    assert_eq!(c.ertm.tx_state, u::TX_STATE_XMIT);
    assert_eq!(c.ertm.rx_state, u::RX_STATE_RECV);
}
