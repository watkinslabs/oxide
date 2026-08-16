//! BR/EDR signalling payloads: every one round-trips, and every wrong-width
//! payload is refused rather than parsed short.

use super::*;

#[test]
fn each_reject_form_round_trips_and_reports_its_reason() {
    for r in [CommandRej::NotUnderstood, CommandRej::MtuExceeded { max_mtu: 48 },
              CommandRej::InvalidCid { scid: 0x0041, dcid: 0x0042 }] {
        let b = r.encode();
        assert_eq!(CommandRej::decode(&b), Some(r));
    }
    assert_eq!(CommandRej::NotUnderstood.encode().len(), u::CMD_REJ_UNK_LEN);
    assert_eq!(CommandRej::MtuExceeded { max_mtu: 0 }.encode().len(), u::CMD_REJ_MTU_LEN);
    assert_eq!(CommandRej::InvalidCid { scid: 0, dcid: 0 }.encode().len(), u::CMD_REJ_CID_LEN);
    assert_eq!(CommandRej::InvalidCid { scid: 1, dcid: 2 }.reason(), u::REJ_INVALID_CID);
}

#[test]
fn a_reject_whose_payload_does_not_match_its_reason_is_refused() {
    // The invalid-identifier form needs two identifiers after the reason.
    assert!(CommandRej::decode(&[0x02, 0x00, 0x41, 0x00]).is_none());
    // The not-understood form carries nothing after the reason.
    assert!(CommandRej::decode(&[0x00, 0x00, 0x01]).is_none());
    // An undefined reason has no known payload at all.
    assert!(CommandRej::decode(&[0x09, 0x00]).is_none());
    assert!(CommandRej::decode(&[0x00]).is_none());
}

#[test]
fn connect_request_and_response_round_trip() {
    let q = ConnReq { psm: u::PSM_RFCOMM, scid: 0x0040 };
    assert_eq!(ConnReq::decode(&q.encode()), Some(q));
    let s = ConnRsp { dcid: 0x0041, scid: 0x0040, result: u::CR_PEND, status: u::CS_AUTHEN_PEND };
    assert_eq!(ConnRsp::decode(&s.encode()), Some(s));
}

#[test]
fn a_connect_payload_of_the_wrong_width_is_refused() {
    let q = ConnReq { psm: 1, scid: 0x0040 };
    let mut b = q.encode();
    b.pop();
    assert!(ConnReq::decode(&b).is_none());
    b = q.encode();
    b.push(0);
    assert!(ConnReq::decode(&b).is_none());
    assert!(ConnRsp::decode(&q.encode()).is_none());
}

#[test]
fn disconnect_round_trips_in_both_directions() {
    let d = Disconn { dcid: 0x0041, scid: 0x0040 };
    assert_eq!(Disconn::decode(&d.encode()), Some(d));
    assert!(Disconn::decode(&[0, 0]).is_none());
}

#[test]
fn an_echo_payload_is_returned_unchanged() {
    assert_eq!(echo_encode(&[9, 8, 7]), alloc::vec![9, 8, 7]);
    assert!(echo_encode(&[]).is_empty());
}

#[test]
fn information_request_round_trips_and_refuses_a_wrong_width() {
    let q = InfoReq { itype: u::IT_FEAT_MASK };
    assert_eq!(InfoReq::decode(&q.encode()), Some(q));
    assert!(InfoReq::decode(&[2]).is_none());
    assert!(InfoReq::decode(&[2, 0, 0]).is_none());
}

#[test]
fn a_feature_mask_response_carries_a_readable_mask() {
    let r = InfoRsp::feat_mask_rsp(local_feat_mask());
    let back = InfoRsp::decode(&r.encode()).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.feat_mask(), Some(local_feat_mask()));
    assert_eq!(back.fixed_chan_mask(), None);
}

#[test]
fn a_fixed_channel_response_pads_its_reserved_bytes() {
    let mask = u::FC_SIG_BREDR | u::FC_SMP_BREDR;
    let r = InfoRsp::fixed_chan_rsp(mask);
    assert_eq!(r.data.len(), u::FIXED_CHAN_MASK_LEN);
    assert_eq!(InfoRsp::decode(&r.encode()).unwrap().fixed_chan_mask(), Some(mask));
}

#[test]
fn a_refused_information_response_yields_no_properties() {
    let r = InfoRsp::not_supported(u::IT_CL_MTU);
    let back = InfoRsp::decode(&r.encode()).unwrap();
    assert_eq!(back.result, u::IR_NOTSUPP);
    assert_eq!(back.feat_mask(), None);
    assert_eq!(back.fixed_chan_mask(), None);
    // A failure result must not be read as properties even for the right type.
    let bad = InfoRsp { itype: u::IT_FEAT_MASK, result: u::IR_NOTSUPP, data: alloc::vec![1, 2, 3, 4] };
    assert_eq!(bad.feat_mask(), None);
}

#[test]
fn an_information_response_shorter_than_its_header_is_refused() {
    assert!(InfoRsp::decode(&[2, 0, 0]).is_none());
    assert!(InfoRsp::decode(&[2, 0, 0, 0]).is_some());
}

#[test]
fn a_mode_is_selected_only_when_both_ends_support_it() {
    assert_eq!(select_mode(u::MODE_ERTM, u::FEAT_ERTM), u::MODE_ERTM);
    assert_eq!(select_mode(u::MODE_ERTM, 0), u::MODE_BASIC);
    assert_eq!(select_mode(u::MODE_STREAMING, u::FEAT_STREAMING), u::MODE_STREAMING);
    assert_eq!(select_mode(u::MODE_STREAMING, u::FEAT_ERTM), u::MODE_BASIC);
    assert_eq!(select_mode(u::MODE_BASIC, u::FEAT_ERTM), u::MODE_BASIC);
    // A mode nobody negotiates over the air never comes out of the selector.
    assert_eq!(select_mode(u::MODE_LE_FLOWCTL, !0), u::MODE_BASIC);
    assert!(!mode_supported(u::MODE_BASIC, !0));
}
