//! Multiplexer command contract: every command round-trips through a real
//! frame, and the address-encoded DLCI field survives the trip.

use crate::rfcomm::frame;
use crate::rfcomm::mcc::{self, Mcc, Msc, Pn, Rls, Rpn};
use crate::uapi::rfcomm as u;

fn round_trip(cr: bool, cmd: Mcc) -> mcc::MccFrame {
    let f = mcc::encode(u::addr(true, 0), cr, &cmd);
    let d = frame::decode(&f).expect("a multiplexer command is a valid frame");
    assert_eq!(d.dlci(), 0, "multiplexer commands travel on the control channel");
    assert_eq!(d.ftype(), u::RFCOMM_UIH);
    mcc::decode(d.payload).expect("decodes")
}

#[test]
fn parameter_negotiation_round_trips() {
    let pn = Pn { dlci: 6, flow_ctrl: u::RFCOMM_PN_CFC_REQ, priority: 7, ack_timer: 0,
                  mtu: 330, max_retrans: 0, credits: u::RFCOMM_DEFAULT_CREDITS };
    let got = round_trip(true, Mcc::Pn(pn));
    assert!(got.cr);
    assert_eq!(got.cmd, Mcc::Pn(pn));
}

#[test]
fn port_negotiation_round_trips() {
    let rpn = Rpn { dlci: 8, bit_rate: u::RFCOMM_RPN_BR_115200,
                    line_settings: u::rpn_line_settings(u::RFCOMM_RPN_DATA_8, u::RFCOMM_RPN_STOP_1, u::RFCOMM_RPN_PARITY_NONE),
                    flow_ctrl: u::RFCOMM_RPN_FLOW_NONE, xon_char: u::RFCOMM_RPN_XON_CHAR,
                    xoff_char: u::RFCOMM_RPN_XOFF_CHAR, param_mask: u::RFCOMM_RPN_PM_ALL };
    assert_eq!(round_trip(true, Mcc::Rpn(rpn)).cmd, Mcc::Rpn(rpn));
}

#[test]
fn the_one_byte_port_negotiation_is_a_query() {
    assert_eq!(round_trip(true, Mcc::RpnQuery(8)).cmd, Mcc::RpnQuery(8));
}

#[test]
fn line_status_and_modem_status_round_trip() {
    assert_eq!(round_trip(true, Mcc::Rls(Rls { dlci: 4, status: 0x0b })).cmd,
               Mcc::Rls(Rls { dlci: 4, status: 0x0b }));
    let v24 = u::RFCOMM_V24_RTC | u::RFCOMM_V24_RTR | u::RFCOMM_V24_DV;
    assert_eq!(round_trip(true, Mcc::Msc(Msc { dlci: 4, v24_sig: v24 })).cmd,
               Mcc::Msc(Msc { dlci: 4, v24_sig: v24 | 0x01 }));
}

#[test]
fn flow_control_and_test_round_trip() {
    assert_eq!(round_trip(true, Mcc::Fcon).cmd, Mcc::Fcon);
    assert_eq!(round_trip(false, Mcc::Fcoff).cmd, Mcc::Fcoff);
    let pattern = alloc::vec![1u8, 2, 3, 4];
    assert_eq!(round_trip(true, Mcc::Test(pattern.clone())).cmd, Mcc::Test(pattern));
    assert_eq!(round_trip(false, Mcc::Nsc(0x21)).cmd, Mcc::Nsc(0x21));
}

#[test]
fn the_command_bit_survives_both_ways() {
    for cr in [true, false] {
        assert_eq!(round_trip(cr, Mcc::Fcon).cr, cr);
    }
}

#[test]
fn the_dlci_field_of_a_modem_status_is_address_encoded() {
    let f = mcc::encode(u::addr(true, 0), true, &Mcc::Msc(Msc { dlci: 6, v24_sig: 0x8c }));
    let d = frame::decode(&f).unwrap();
    // header type, header length, then the payload's first byte.
    let dlci_field = d.payload[2];
    assert_eq!(dlci_field, u::addr(true, 6), "not the raw DLCI");
    assert_eq!(u::get_dlci(dlci_field), 6);
}

#[test]
fn a_truncated_payload_is_refused() {
    let mut body = alloc::vec![u::mcc_type(true, u::RFCOMM_PN), u::len8(u::RFCOMM_PN_LEN)];
    body.extend_from_slice(&[0u8; 3]);
    assert!(mcc::decode(&body).is_none());
    assert!(mcc::decode(&[u::mcc_type(true, u::RFCOMM_PN)]).is_none());
}

#[test]
fn an_unknown_command_keeps_its_type() {
    let body = alloc::vec![u::mcc_type(true, 0x11), u::len8(0)];
    assert_eq!(mcc::decode(&body).unwrap().cmd, Mcc::Unknown(0x11));
}

#[test]
fn the_mcc_header_packs_and_unpacks() {
    for ty in [u::RFCOMM_PN, u::RFCOMM_RPN, u::RFCOMM_RLS, u::RFCOMM_MSC,
               u::RFCOMM_FCON, u::RFCOMM_FCOFF, u::RFCOMM_TEST, u::RFCOMM_NSC] {
        for cr in [true, false] {
            let b = u::mcc_type(cr, ty);
            assert_eq!(u::get_mcc_type(b), ty);
            assert_eq!(u::test_cr(b), cr);
            assert!(u::test_ea(b));
        }
    }
    for len in 0..64usize { assert_eq!(u::get_mcc_len(u::len8(len)), len); }
}
