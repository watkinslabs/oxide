// The block-ack negotiation decisions.

use wireless::ieee80211::mgmt::{ba_params, AddbaReq, AddbaResp, Delba};
use wireless::ieee80211::status::status;

use crate::agg::action::{self, FIRST_TSPEC_TID};
use crate::agg::tid_tx::{TidTx, TxAggState};
use crate::limits;

fn req(tid: u8, buf: u16, immediate: bool) -> AddbaReq {
    AddbaReq {
        dialog_token: 1,
        params: ba_params::build(tid, buf, false, immediate),
        timeout: 0,
        start_seq_num: 100,
    }
}

#[test]
fn a_well_formed_request_is_accepted_with_the_buffer_both_ends_can_hold() {
    let d = action::on_addba_req(&req(3, 32, true), 64);
    assert!(d.accepted());
    assert_eq!(d.tid, 3);
    assert_eq!(d.buf_size, 32);
    assert_eq!(d.ssn, 100);
}

#[test]
fn a_request_for_more_than_this_radio_holds_is_answered_with_what_it_holds() {
    let d = action::on_addba_req(&req(0, 512, true), 64);
    assert!(d.accepted());
    assert_eq!(d.buf_size, 64);
}

#[test]
fn a_request_naming_no_buffer_gets_the_largest_rather_than_none() {
    // Honouring a zero literally makes a session that can never release a
    // frame, which stalls the traffic identifier for as long as it lives.
    let d = action::on_addba_req(&req(0, 0, true), 64);
    assert!(d.accepted());
    assert_eq!(d.buf_size, 64);
    assert!(d.buf_size >= limits::MIN_AGG_BUF_SIZE);
}

#[test]
fn the_delayed_policy_is_refused_with_a_parameter_error() {
    // Accepting it and then behaving as if it were immediate leaves the two
    // ends disagreeing about when an acknowledgement is due.
    let d = action::on_addba_req(&req(0, 32, false), 64);
    assert!(!d.accepted());
    assert_eq!(d.status, status::INVALID_QOS_PARAM);
}

#[test]
fn an_identifier_outside_the_block_ack_range_is_declined() {
    for tid in FIRST_TSPEC_TID..16 {
        let d = action::on_addba_req(&req(tid, 32, true), 64);
        assert!(!d.accepted(), "tid {tid}");
        assert_eq!(d.status, status::REQUEST_DECLINED);
    }
    for tid in 0..FIRST_TSPEC_TID {
        assert!(action::on_addba_req(&req(tid, 32, true), 64).accepted(), "tid {tid}");
    }
}

#[test]
fn the_widest_request_the_field_can_carry_is_agreed_down() {
    // The parameter field is ten bits, so the largest a peer can ask for is
    // within the protocol's ceiling; what it exceeds is this radio's own.
    let mut r = req(0, 0, true);
    r.params |= ba_params::BUFSIZE_MASK;
    let asked = ba_params::buf_size(r.params);
    assert!(asked <= limits::MAX_AGG_BUF_SIZE);
    let d = action::on_addba_req(&r, 64);
    assert!(d.accepted());
    assert_eq!(d.buf_size, 64);
}

#[test]
fn the_response_parameters_echo_what_was_agreed() {
    let d = action::on_addba_req(&req(5, 16, true), 64);
    let p = d.resp_params();
    assert_eq!(ba_params::tid(p), 5);
    assert_eq!(ba_params::buf_size(p), 16);
    assert_ne!(p & ba_params::POLICY, 0, "the answer names the immediate policy");
}

#[test]
fn a_successful_response_is_read_as_an_agreement() {
    let resp = AddbaResp {
        dialog_token: 9,
        status: status::SUCCESS,
        params: ba_params::build(2, 32, false, true),
        timeout: 0,
    };
    let o = action::on_addba_resp(&resp);
    assert!(o.accepted);
    assert_eq!((o.tid, o.buf_size, o.dialog_token), (2, 32, 9));
}

#[test]
fn a_success_naming_an_unusable_session_is_read_as_a_refusal() {
    // A response that says success but names a buffer of zero, an identifier
    // out of range, or the delayed policy describes a session neither end
    // could use.
    for params in [ba_params::build(2, 0, false, true),
                   ba_params::build(9, 32, false, true),
                   ba_params::build(2, 32, false, false)] {
        let resp = AddbaResp { dialog_token: 1, status: status::SUCCESS, params, timeout: 0 };
        assert!(!action::on_addba_resp(&resp).accepted, "params {params:#06x}");
    }
}

#[test]
fn a_refusal_is_a_refusal() {
    let resp = AddbaResp {
        dialog_token: 1, status: status::REQUEST_DECLINED,
        params: ba_params::build(2, 32, false, true), timeout: 0,
    };
    assert!(!action::on_addba_resp(&resp).accepted);
}

#[test]
fn a_teardown_names_which_half_of_the_session_it_ends() {
    let mut params = (4u16 << ba_params::DELBA_TID_SHIFT) & ba_params::DELBA_TID_MASK;
    let d = action::on_delba(&Delba { params, reason: 7 });
    assert_eq!(d.tid, 4);
    assert!(!d.initiator, "the recipient is tearing down its own transmit half");
    params |= ba_params::DELBA_INITIATOR;
    let d = action::on_delba(&Delba { params, reason: 7 });
    assert!(d.initiator);
    assert_eq!(d.reason, 7);
}

#[test]
fn a_session_is_not_worth_setting_up_until_it_has_carried_traffic() {
    let mut t = TidTx::new(0);
    assert!(!t.should_start());
    t.pending_count = limits::AGG_START_THRESHOLD - 1;
    assert!(!t.should_start());
    t.pending_count = limits::AGG_START_THRESHOLD;
    assert!(t.should_start());
}

#[test]
fn a_session_carries_nothing_until_the_peer_has_agreed() {
    let mut t = TidTx::new(50);
    assert!(!t.is_operational());
    t.request_sent(3, 0);
    assert_eq!(t.state, TxAggState::WantStart);
    assert!(!t.is_operational(), "frames sent before agreement are discarded by the peer");
    assert!(t.response(3, true, 32));
    assert!(t.is_operational());
    assert_eq!(t.buf_size, 32);
}

#[test]
fn a_response_for_an_abandoned_attempt_is_ignored() {
    let mut t = TidTx::new(0);
    t.request_sent(3, 0);
    assert!(!t.response(4, true, 32), "a different token belongs to another attempt");
    assert!(!t.is_operational());
    assert!(t.response(3, true, 32));
}

#[test]
fn a_refused_session_goes_back_to_idle_and_may_be_tried_again() {
    let mut t = TidTx::new(0);
    t.request_sent(1, 0);
    assert!(t.response(1, false, 0));
    assert_eq!(t.state, TxAggState::Idle);
    assert_eq!(t.tries, 0);
}

#[test]
fn an_unanswered_request_times_out_and_is_retried_to_a_limit() {
    let mut t = TidTx::new(0);
    let mut now = 0u64;
    for _ in 0..limits::ADDBA_MAX_TRIES {
        assert!(t.may_retry());
        t.request_sent(1, now);
        assert!(!t.request_timed_out(now + limits::ADDBA_RESP_TIMEOUT_NS - 1));
        now += limits::ADDBA_RESP_TIMEOUT_NS;
        assert!(t.request_timed_out(now));
    }
    assert!(!t.may_retry());
}

#[test]
fn an_operational_session_that_carries_nothing_goes_idle() {
    let mut t = TidTx::new(0);
    t.request_sent(1, 0);
    t.response(1, true, 32);
    t.last_tx_ns = 1_000;
    assert!(!t.is_idle(1_000 + limits::AGG_SESSION_TIMEOUT_NS - 1));
    assert!(t.is_idle(1_000 + limits::AGG_SESSION_TIMEOUT_NS));
    // A session that never started is not idle; it is absent.
    assert!(!TidTx::new(0).is_idle(u64::MAX));
}
