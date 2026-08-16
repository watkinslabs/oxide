//! Credit-flow contract. These are the checks whose failure produces a wedged
//! or desynchronised link rather than a loud error: transmission must stop at
//! zero, and a top-up must grant the difference and not the ceiling.

use crate::rfcomm::credit::{CreditFlow, NONCFC_TX_CREDITS};
use crate::rfcomm::mcc::Pn;
use crate::uapi::rfcomm as u;

fn pn(flow_ctrl: u8, credits: u8) -> Pn {
    Pn { dlci: 4, flow_ctrl, priority: 7, ack_timer: 0, mtu: 127, max_retrans: 0, credits }
}

#[test]
fn the_request_and_response_values_turn_credit_flow_on() {
    for flow in [u::RFCOMM_PN_CFC_REQ, u::RFCOMM_PN_CFC_RSP] {
        let mut c = CreditFlow::new();
        let session = c.apply_pn(&pn(flow, 7), u::RFCOMM_CFC_UNKNOWN);
        assert!(c.enabled(), "flow 0x{flow:x} must enable credit flow");
        assert_eq!(session, u::RFCOMM_CFC_ENABLED);
        assert_eq!(c.ceiling(), u::RFCOMM_MAX_CREDITS as u16);
        assert_eq!(c.tx_credits, 7);
    }
}

#[test]
fn any_other_value_turns_credit_flow_off_and_parks_transmission() {
    for flow in [0x00u8, 0x01, 0x0f, 0xf1, 0xe1, 0xff] {
        let mut c = CreditFlow::new();
        let session = c.apply_pn(&pn(flow, 7), u::RFCOMM_CFC_UNKNOWN);
        assert!(!c.enabled(), "flow 0x{flow:x} must not enable credit flow");
        assert_eq!(session, u::RFCOMM_CFC_DISABLED);
        assert!(c.tx_throttled);
    }
}

#[test]
fn a_request_cannot_re_enable_credit_flow_a_session_settled_off() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_REQ, 7), u::RFCOMM_CFC_DISABLED);
    assert!(!c.enabled());
    // The response value still does, since it answers a request this end made.
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 7), u::RFCOMM_CFC_DISABLED);
    assert!(c.enabled());
}

#[test]
fn a_poll_bit_frame_gives_up_its_credit_byte() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 0), u::RFCOMM_CFC_UNKNOWN);
    assert_eq!(c.tx_credits, 0);
    let payload = [5u8, b'h', b'i'];
    let rest = c.take_grant(true, &payload).expect("a credit byte is present");
    assert_eq!(rest, b"hi", "the credit byte is removed from the payload");
    assert_eq!(c.tx_credits, 5);
    assert!(!c.tx_throttled, "a grant releases the transmitter");
}

#[test]
fn a_frame_without_the_poll_bit_keeps_its_whole_payload() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 3), u::RFCOMM_CFC_UNKNOWN);
    let rest = c.take_grant(false, b"hi").unwrap();
    assert_eq!(rest, b"hi");
    assert_eq!(c.tx_credits, 3);
}

#[test]
fn a_poll_bit_frame_with_no_byte_is_truncated() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 3), u::RFCOMM_CFC_UNKNOWN);
    assert!(c.take_grant(true, &[]).is_none());
}

#[test]
fn transmission_blocks_at_zero_credits_and_a_grant_releases_it() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 2), u::RFCOMM_CFC_UNKNOWN);
    assert!(c.can_send());
    c.on_frame_sent();
    assert!(c.can_send());
    c.on_frame_sent();
    assert_eq!(c.tx_credits, 0);
    assert!(!c.can_send(), "no credit means no transmission");
    assert!(c.tx_throttled);
    // The credit count, not only the throttle flag, is what blocks: clearing
    // the flag by hand must not let a frame out.
    c.tx_throttled = false;
    assert!(!c.can_send(), "zero credits blocks with nothing throttled");
    c.take_grant(true, &[4]).unwrap();
    assert!(c.can_send());
    assert_eq!(c.tx_credits, 4);
}

#[test]
fn the_top_up_fires_at_a_quarter_of_the_ceiling_and_grants_the_difference() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 7), u::RFCOMM_CFC_UNKNOWN);
    let ceiling = c.ceiling();
    c.rx_credits = ceiling;
    // Nothing is due while the allowance is above a quarter.
    for held in (ceiling >> 2) + 1..=ceiling {
        c.rx_credits = held;
        assert_eq!(c.topup(), None, "no top-up while {held} credits are held");
    }
    // At the threshold exactly, the difference is granted.
    let threshold = ceiling >> 2;
    c.rx_credits = threshold;
    assert_eq!(c.topup(), Some((ceiling - threshold) as u8));
    assert_eq!(c.rx_credits, ceiling);
    // And below it.
    c.rx_credits = 0;
    assert_eq!(c.topup(), Some(ceiling as u8));
    assert_eq!(c.rx_credits, ceiling);
}

#[test]
fn the_top_up_never_grants_more_than_the_peer_can_hold() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 7), u::RFCOMM_CFC_UNKNOWN);
    let ceiling = c.ceiling();
    // Model the peer's view: it holds what it was granted and spends one per
    // frame. Granting the ceiling instead of the difference inflates it.
    let mut peer_holds: u16 = 0;
    c.rx_credits = ceiling;
    peer_holds += ceiling;
    for _ in 0..200 {
        if peer_holds == 0 { break; }
        peer_holds -= 1;
        c.on_frame_received();
        if let Some(g) = c.topup() { peer_holds += g as u16; }
        assert!(peer_holds <= ceiling, "the peer's allowance ran past the ceiling");
        assert_eq!(peer_holds, c.rx_credits, "the two ends disagree about the allowance");
    }
}

#[test]
fn a_throttled_receiver_grants_nothing() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(u::RFCOMM_PN_CFC_RSP, 7), u::RFCOMM_CFC_UNKNOWN);
    c.rx_credits = 0;
    c.rx_throttled = true;
    assert_eq!(c.topup(), None);
}

#[test]
fn a_link_without_credit_flow_refills_its_own_batch() {
    let mut c = CreditFlow::new();
    c.apply_pn(&pn(0, 0), u::RFCOMM_CFC_UNKNOWN);
    assert_eq!(c.topup(), None, "there are no credits to grant");
    c.refill_noncfc();
    assert_eq!(c.tx_credits, NONCFC_TX_CREDITS);
    c.tx_throttled = false;
    for _ in 0..NONCFC_TX_CREDITS { assert!(c.can_send()); c.on_frame_sent(); }
    assert!(!c.can_send());
    assert!(!c.tx_throttled, "a link without credit flow is not parked by an empty batch");
}

#[test]
fn a_fresh_link_starts_with_the_default_receive_allowance() {
    let c = CreditFlow::new();
    assert_eq!(c.rx_credits, u::RFCOMM_DEFAULT_CREDITS as u16);
    assert_eq!(c.tx_credits, 0);
    assert!(!c.enabled());
}
