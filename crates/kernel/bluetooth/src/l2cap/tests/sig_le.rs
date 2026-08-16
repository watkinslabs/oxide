//! LE signalling payloads, including the identifier arrays whose length must
//! be a whole number of identifiers and no longer than the protocol permits.

use super::*;
use alloc::vec;

#[test]
fn the_parameter_update_exchange_round_trips() {
    let q = ConnParamUpdateReq { min: 6, max: 12, latency: 0, to_multiplier: 200 };
    assert_eq!(ConnParamUpdateReq::decode(&q.encode()), Some(q));
    let s = ConnParamUpdateRsp { result: u::CONN_PARAM_REJECTED };
    assert_eq!(ConnParamUpdateRsp::decode(&s.encode()), Some(s));
    assert!(ConnParamUpdateReq::decode(&q.encode()[..7]).is_none());
    assert!(ConnParamUpdateRsp::decode(&[0]).is_none());
}

#[test]
fn the_credit_based_connect_exchange_round_trips() {
    let q = LeConnReq { psm: 0x0080, scid: 0x0040, mtu: 512, mps: 251, credits: 10 };
    assert_eq!(LeConnReq::decode(&q.encode()), Some(q));
    let s = LeConnRsp { dcid: 0x0041, mtu: 512, mps: 251, credits: 10, result: u::CR_LE_SUCCESS };
    assert_eq!(LeConnRsp::decode(&s.encode()), Some(s));
}

#[test]
fn a_credit_based_connect_payload_of_the_wrong_width_is_refused() {
    let q = LeConnReq { psm: 1, scid: 0x0040, mtu: 23, mps: 23, credits: 0 };
    let mut b = q.encode();
    b.push(0);
    assert!(LeConnReq::decode(&b).is_none());
    assert!(LeConnReq::decode(&b[..9]).is_none());
}

#[test]
fn a_credit_grant_round_trips() {
    let g = LeCredits { cid: 0x0040, credits: 65535 };
    assert_eq!(LeCredits::decode(&g.encode()), Some(g));
    assert!(LeCredits::decode(&[0, 0, 0]).is_none());
}

#[test]
fn the_enhanced_connect_exchange_round_trips_with_its_identifiers() {
    let q = EcredConnReq { psm: 0x0081, mtu: 64, mps: 64, credits: 5, scids: vec![0x0040, 0x0041] };
    assert_eq!(EcredConnReq::decode(&q.encode().unwrap()), Some(q.clone()));
    let s = EcredConnRsp { mtu: 64, mps: 64, credits: 5, result: u::CR_LE_SUCCESS, dcids: vec![0x0050, 0] };
    assert_eq!(EcredConnRsp::decode(&s.encode().unwrap()), Some(s));
}

#[test]
fn an_enhanced_connect_with_no_identifiers_is_still_well_formed() {
    let q = EcredConnReq { psm: 0x0081, mtu: 64, mps: 64, credits: 5, scids: vec![] };
    assert_eq!(EcredConnReq::decode(&q.encode().unwrap()), Some(q));
}

#[test]
fn an_identifier_array_of_a_half_identifier_is_refused() {
    let q = EcredConnReq { psm: 1, mtu: 64, mps: 64, credits: 1, scids: vec![0x0040] };
    let mut b = q.encode().unwrap();
    b.pop();
    assert!(EcredConnReq::decode(&b).is_none());
}

#[test]
fn an_identifier_array_past_the_ceiling_is_refused_both_ways() {
    let too_many: alloc::vec::Vec<u16> = (0..u::ECRED_MAX_CID as u16 + 1).map(|i| 0x0040 + i).collect();
    let q = EcredConnReq { psm: 1, mtu: 64, mps: 64, credits: 1, scids: too_many.clone() };
    assert!(q.encode().is_none());
    // Built by hand, such a request must still be refused on receipt.
    let mut b = alloc::vec::Vec::new();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&64u16.to_le_bytes());
    b.extend_from_slice(&64u16.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    for c in &too_many { b.extend_from_slice(&c.to_le_bytes()); }
    assert!(EcredConnReq::decode(&b).is_none());
}

#[test]
fn the_reconfigure_exchange_round_trips() {
    let q = EcredReconfReq { mtu: 128, mps: 96, scids: vec![0x0040, 0x0041, 0x0042] };
    assert_eq!(EcredReconfReq::decode(&q.encode().unwrap()), Some(q));
    let s = EcredReconfRsp { result: u::RECONF_INVALID_MPS };
    assert_eq!(EcredReconfRsp::decode(&s.encode()), Some(s));
    assert!(EcredReconfReq::decode(&[0, 0, 0]).is_none());
    assert!(EcredReconfRsp::decode(&[0, 0, 0]).is_none());
}

#[test]
fn the_two_signalling_channels_carry_disjoint_command_sets_apart_from_the_shared_ones() {
    assert!(le_sig_code(u::LE_CONN_REQ) && !bredr_sig_code(u::LE_CONN_REQ));
    assert!(bredr_sig_code(u::CONF_REQ) && !le_sig_code(u::CONF_REQ));
    assert!(bredr_sig_code(u::ECHO_REQ) && !le_sig_code(u::ECHO_REQ));
    for shared in [u::COMMAND_REJ, u::DISCONN_REQ, u::DISCONN_RSP] {
        assert!(le_sig_code(shared) && bredr_sig_code(shared));
    }
    assert!(!le_sig_code(0xff) && !bredr_sig_code(0xff));
}
