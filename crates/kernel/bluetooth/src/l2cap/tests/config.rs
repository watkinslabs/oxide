//! Configuration negotiation: a normal exchange settles both directions, an
//! unusable MTU is answered rather than accepted, and an unknown option is
//! named back to the sender unless it was only a hint.

use super::*;
use super::super::sig_conf::encode_opts;
use alloc::vec;

fn basic_link() -> LinkCaps { LinkCaps { mtu: 1017, feat_mask: 0 } }
fn ertm_link() -> LinkCaps {
    LinkCaps { mtu: 1017, feat_mask: u::FEAT_ERTM | u::FEAT_STREAMING | u::FEAT_FCS | u::FEAT_EXT_WINDOW }
}

fn opts(v: &[RawOpt]) -> alloc::vec::Vec<u8> { encode_opts(v).unwrap() }

#[test]
fn a_normal_exchange_settles_both_directions() {
    let mut chan = Channel::new();
    // The peer proposes an MTU we can meet.
    let req = opts(&[RawOpt::le16(u::CONF_MTU, 672)]);
    let handled = conf_req_received(&mut chan, basic_link(), 0, &req).unwrap();
    let ReqHandled::Answer(ans) = handled else { panic!("expected an answer") };
    assert_eq!(ans.result, u::CONF_SUCCESS);
    assert!(chan.conf(CONF_OUTPUT_DONE));
    assert!(chan.conf(CONF_MTU_DONE));
    assert_eq!(chan.omtu, 672);
    assert!(!chan.conf_complete());

    // The peer accepts ours.
    let rsp = conf_rsp_received(&mut chan, 0, u::CONF_SUCCESS, &[]).unwrap();
    assert_eq!(rsp, RspHandled::InputDone);
    assert!(chan.conf(CONF_INPUT_DONE));
    assert!(chan.conf_complete());
}

#[test]
fn an_mtu_below_the_floor_is_answered_unacceptable_with_the_value_we_can_take() {
    let mut chan = Channel::new();
    let req = opts(&[RawOpt::le16(u::CONF_MTU, u::DEFAULT_MIN_MTU - 1)]);
    let ans = parse_conf_req(&mut chan, basic_link(), &req).unwrap();
    assert_eq!(ans.result, u::CONF_UNACCEPT);
    // The answer names the MTU, so the peer learns what to propose next.
    let mtu = ans.opts.iter().find(|o| o.otype == u::CONF_MTU).expect("mtu named");
    assert_eq!(mtu.as_le16(), Some(chan.omtu));
    assert!(!chan.conf(CONF_OUTPUT_DONE));
    assert!(!chan.conf(CONF_MTU_DONE));
}

#[test]
fn an_absent_mtu_is_taken_as_the_default() {
    let mut chan = Channel::new();
    let ans = parse_conf_req(&mut chan, basic_link(), &[]).unwrap();
    assert_eq!(ans.result, u::CONF_SUCCESS);
    assert_eq!(chan.omtu, u::DEFAULT_MTU);
}

#[test]
fn an_unknown_option_is_named_back_to_the_sender() {
    let mut chan = Channel::new();
    let unknown = 0x40u8;
    let req = opts(&[RawOpt::le16(u::CONF_MTU, 672), RawOpt::byte(unknown, 1)]);
    let ans = parse_conf_req(&mut chan, basic_link(), &req).unwrap();
    assert_eq!(ans.result, u::CONF_UNKNOWN);
    assert!(ans.opts.iter().any(|o| o.otype == unknown));
    // An unknown option leaves the direction unsettled.
    assert!(!chan.conf(CONF_OUTPUT_DONE));
}

#[test]
fn an_unknown_option_marked_as_a_hint_is_ignored() {
    let mut chan = Channel::new();
    let unknown = 0x40u8;
    let req = opts(&[
        RawOpt::le16(u::CONF_MTU, 672),
        RawOpt { otype: unknown, hint: true, val: vec![1] },
    ]);
    let ans = parse_conf_req(&mut chan, basic_link(), &req).unwrap();
    assert_eq!(ans.result, u::CONF_SUCCESS);
    assert!(!ans.opts.iter().any(|o| o.otype == unknown));
    assert!(chan.conf(CONF_OUTPUT_DONE));
}

#[test]
fn a_flush_timeout_in_a_request_is_taken_as_proposed() {
    let mut chan = Channel::new();
    let req = opts(&[RawOpt::le16(u::CONF_FLUSH_TO, 1234)]);
    parse_conf_req(&mut chan, basic_link(), &req).unwrap();
    assert_eq!(chan.flush_to, 1234);
}

#[test]
fn a_peer_asking_for_no_frame_check_sequence_is_recorded() {
    let mut chan = Channel::new();
    let req = opts(&[RawOpt::byte(u::CONF_FCS, u::FCS_NONE)]);
    parse_conf_req(&mut chan, basic_link(), &req).unwrap();
    assert!(chan.conf(CONF_RECV_NO_FCS));
}

#[test]
fn an_extended_window_option_in_a_request_refuses_the_channel() {
    let mut chan = Channel::new();
    let req = opts(&[RawOpt::le16(u::CONF_EWS, 200)]);
    assert_eq!(parse_conf_req(&mut chan, basic_link(), &req), Err(Refused));
}

#[test]
fn a_multipart_request_is_answered_only_once_it_is_whole() {
    let mut chan = Channel::new();
    let first = opts(&[RawOpt::le16(u::CONF_FLUSH_TO, 99)]);
    let handled = conf_req_received(&mut chan, basic_link(), u::CONF_FLAG_CONTINUATION, &first).unwrap();
    assert_eq!(handled, ReqHandled::Continuation);
    assert!(!chan.conf(CONF_OUTPUT_DONE));
    let second = opts(&[RawOpt::le16(u::CONF_MTU, 672)]);
    let handled = conf_req_received(&mut chan, basic_link(), 0, &second).unwrap();
    assert!(matches!(handled, ReqHandled::Answer(_)));
    // Both parts were considered.
    assert_eq!(chan.flush_to, 99);
    assert_eq!(chan.omtu, 672);
    assert!(chan.conf_req.is_empty());
}

#[test]
fn a_request_larger_than_the_accumulation_buffer_is_rejected() {
    let mut chan = Channel::new();
    let big = vec![0u8; super::super::chan::CONF_BUF_SIZE + 1];
    assert_eq!(conf_req_received(&mut chan, basic_link(), 0, &big).unwrap(), ReqHandled::TooLarge);
}

#[test]
fn a_disagreement_produces_a_further_request_until_the_round_limit() {
    let mut chan = Channel::new();
    let counter = opts(&[RawOpt::le16(u::CONF_MTU, 512)]);
    let r = conf_rsp_received(&mut chan, 0, u::CONF_UNACCEPT, &counter).unwrap();
    assert!(matches!(r, RspHandled::Retry(_)));
    assert_eq!(chan.imtu, 512);
    assert!(!chan.conf(CONF_INPUT_DONE));
    // Past the limit the two ends cannot agree.
    chan.num_conf_rsp = u::CONF_MAX_CONF_RSP + 1;
    assert_eq!(conf_rsp_received(&mut chan, 0, u::CONF_UNACCEPT, &counter), Err(Refused));
}

#[test]
fn a_response_naming_an_mtu_below_the_floor_is_clamped_and_marked_unacceptable() {
    let mut chan = Channel::new();
    let mut result = u::CONF_SUCCESS;
    let rsp = opts(&[RawOpt::le16(u::CONF_MTU, 1)]);
    parse_conf_rsp(&mut chan, &rsp, &mut result).unwrap();
    assert_eq!(result, u::CONF_UNACCEPT);
    assert_eq!(chan.imtu, u::DEFAULT_MIN_MTU);
}

#[test]
fn an_unrecognised_verdict_ends_the_channel() {
    let mut chan = Channel::new();
    assert_eq!(conf_rsp_received(&mut chan, 0, u::CONF_REJECT, &[]), Err(Refused));
    assert_eq!(conf_rsp_received(&mut chan, 0, 0x00ff, &[]), Err(Refused));
}

#[test]
fn a_continuation_response_settles_nothing() {
    let mut chan = Channel::new();
    let r = conf_rsp_received(&mut chan, u::CONF_FLAG_CONTINUATION, u::CONF_SUCCESS, &[]).unwrap();
    assert_eq!(r, RspHandled::Pending);
    assert!(!chan.conf(CONF_INPUT_DONE));
}

#[test]
fn a_proposal_asks_for_the_mode_the_peer_can_actually_run() {
    let mut chan = Channel::new();
    chan.mode = u::MODE_ERTM;
    let out = build_conf_req(&mut chan, ertm_link());
    assert_eq!(chan.mode, u::MODE_ERTM);
    let rfc = out.iter().find(|o| o.otype == u::CONF_RFC).expect("mode named");
    assert_eq!(Rfc::decode(&rfc.val).unwrap().mode, u::MODE_ERTM);

    // With a peer that supports neither, the same channel proposes basic.
    let mut plain = Channel::new();
    plain.mode = u::MODE_ERTM;
    let out = build_conf_req(&mut plain, basic_link());
    assert_eq!(plain.mode, u::MODE_BASIC);
    assert!(!out.iter().any(|o| o.otype == u::CONF_RFC));
}

#[test]
fn a_proposal_names_the_receive_mtu_only_when_it_differs_from_the_default() {
    let mut chan = Channel::new();
    assert!(!build_conf_req(&mut chan, basic_link()).iter().any(|o| o.otype == u::CONF_MTU));
    let mut other = Channel::new();
    other.imtu = 1000;
    assert!(build_conf_req(&mut other, basic_link()).iter().any(|o| o.otype == u::CONF_MTU));
}

#[test]
fn a_state_two_device_refuses_a_mode_it_did_not_ask_for() {
    let mut chan = Channel::new();
    chan.mode = u::MODE_ERTM;
    chan.set_conf(CONF_STATE2_DEVICE);
    let req = opts(&[Rfc::basic().opt()]);
    assert_eq!(parse_conf_req(&mut chan, ertm_link(), &req), Err(Refused));
}

#[test]
fn a_mode_mismatch_is_answered_with_a_counter_proposal_before_it_is_refused() {
    let mut chan = Channel::new();
    chan.mode = u::MODE_ERTM;
    chan.num_conf_rsp = 1;
    chan.num_conf_req = 2;
    let req = opts(&[Rfc::basic().opt()]);
    // The second disagreement in a row is a refusal.
    assert_eq!(parse_conf_req(&mut chan, ertm_link(), &req), Err(Refused));
}

#[test]
fn the_payload_bound_never_exceeds_what_the_link_can_carry() {
    assert_eq!(max_pdu_for_link(1017), u::DEFAULT_MAX_PDU_SIZE.min(1017 - 12));
    assert_eq!(max_pdu_for_link(4096), u::DEFAULT_MAX_PDU_SIZE);
    assert_eq!(max_pdu_for_link(8), 0);
}

#[test]
fn a_successful_response_applies_the_parameters_it_confirmed() {
    let mut chan = Channel::new();
    chan.mode = u::MODE_ERTM;
    chan.ack_win = u::DEFAULT_TX_WINDOW;
    let rfc = Rfc { mode: u::MODE_ERTM, txwin_size: 10, max_transmit: 3, retrans_timeout: 1000, monitor_timeout: 5000, max_pdu_size: 400 };
    conf_rfc_get(&mut chan, &opts(&[rfc.opt()]));
    assert_eq!(chan.mps, 400);
    assert_eq!(chan.retrans_timeout, 1000);
    assert_eq!(chan.monitor_timeout, 5000);
    assert_eq!(chan.ack_win, 10);
}
