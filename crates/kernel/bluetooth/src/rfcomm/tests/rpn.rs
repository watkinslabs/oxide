//! Port-negotiation contract: the mask decides what changes, and the reply
//! clears the bit of anything that was not accepted.

use crate::rfcomm::mcc::Rpn;
use crate::rfcomm::rpn::{self, PortSettings};
use crate::uapi::rfcomm as u;

fn req(mask: u16) -> Rpn {
    Rpn {
        dlci: 4,
        bit_rate: u::RFCOMM_RPN_BR_115200,
        line_settings: u::rpn_line_settings(u::RFCOMM_RPN_DATA_5, u::RFCOMM_RPN_STOP_15, u::RFCOMM_RPN_PARITY_ODD),
        flow_ctrl: 0x40,
        xon_char: 0x01,
        xoff_char: 0x02,
        param_mask: mask,
    }
}

#[test]
fn line_settings_pack_and_unpack() {
    for data in 0..4u8 {
        for stop in 0..2u8 {
            for parity in [u::RFCOMM_RPN_PARITY_NONE, u::RFCOMM_RPN_PARITY_ODD,
                           u::RFCOMM_RPN_PARITY_EVEN, u::RFCOMM_RPN_PARITY_MARK,
                           u::RFCOMM_RPN_PARITY_SPACE] {
                let b = u::rpn_line_settings(data, stop, parity);
                assert_eq!(u::get_rpn_data_bits(b), data);
                assert_eq!(u::get_rpn_stop_bits(b), stop);
                assert_eq!(u::get_rpn_parity(b), parity);
            }
        }
    }
}

#[test]
fn a_parameter_outside_the_mask_is_not_changed() {
    let before = PortSettings::new();
    let mut p = before;
    p.apply(&req(u::RFCOMM_RPN_PM_BITRATE));
    assert_eq!(p.bit_rate, u::RFCOMM_RPN_BR_115200, "the named parameter changed");
    assert_eq!(p.data_bits, before.data_bits);
    assert_eq!(p.stop_bits, before.stop_bits);
    assert_eq!(p.parity, before.parity);
    assert_eq!(p.flow_ctrl, before.flow_ctrl);
    assert_eq!(p.xon_char, before.xon_char);
    assert_eq!(p.xoff_char, before.xoff_char);
}

#[test]
fn an_empty_mask_changes_nothing() {
    let before = PortSettings::new();
    let mut p = before;
    p.apply(&req(0));
    assert_eq!(p, before);
}

#[test]
fn every_mask_bit_moves_only_its_own_parameter() {
    let base = PortSettings::new();
    let cases: [(u16, fn(&PortSettings) -> u32); 6] = [
        (u::RFCOMM_RPN_PM_BITRATE, |p| p.bit_rate as u32),
        (u::RFCOMM_RPN_PM_DATA,    |p| p.data_bits as u32),
        (u::RFCOMM_RPN_PM_STOP,    |p| p.stop_bits as u32),
        (u::RFCOMM_RPN_PM_PARITY,  |p| p.parity as u32),
        (u::RFCOMM_RPN_PM_XON,     |p| p.xon_char as u32),
        (u::RFCOMM_RPN_PM_XOFF,    |p| p.xoff_char as u32),
    ];
    for (bit, read) in cases {
        let mut p = base;
        p.apply(&req(bit));
        assert_ne!(read(&p), read(&base), "mask 0x{bit:x} did not take");
        for (other, read_other) in cases {
            if other == bit { continue; }
            assert_eq!(read_other(&p), read_other(&base), "mask 0x{bit:x} disturbed 0x{other:x}");
        }
    }
}

#[test]
fn the_reply_clears_the_bit_of_a_parameter_that_was_refused() {
    let r = rpn::negotiate(&req(u::RFCOMM_RPN_PM_ALL));
    assert_eq!(r.param_mask & u::RFCOMM_RPN_PM_DATA, 0, "five data bits are not carried");
    assert_eq!(r.param_mask & u::RFCOMM_RPN_PM_STOP, 0);
    assert_eq!(r.param_mask & u::RFCOMM_RPN_PM_PARITY, 0);
    assert_eq!(r.param_mask & u::RFCOMM_RPN_PM_FLOW, 0);
    assert_eq!(r.param_mask & u::RFCOMM_RPN_PM_XON, 0);
    assert_eq!(r.param_mask & u::RFCOMM_RPN_PM_XOFF, 0);
    assert_ne!(r.param_mask & u::RFCOMM_RPN_PM_BITRATE, 0, "a valid bit rate is accepted");
    assert_eq!(r.bit_rate, u::RFCOMM_RPN_BR_115200);
    assert_eq!(u::get_rpn_data_bits(r.line_settings), u::RFCOMM_RPN_DATA_8);
}

#[test]
fn an_acceptable_request_keeps_every_bit() {
    let good = Rpn {
        dlci: 4, bit_rate: u::RFCOMM_RPN_BR_9600,
        line_settings: u::rpn_line_settings(u::RFCOMM_RPN_DATA_8, u::RFCOMM_RPN_STOP_1, u::RFCOMM_RPN_PARITY_NONE),
        flow_ctrl: u::RFCOMM_RPN_FLOW_NONE, xon_char: u::RFCOMM_RPN_XON_CHAR,
        xoff_char: u::RFCOMM_RPN_XOFF_CHAR, param_mask: u::RFCOMM_RPN_PM_ALL,
    };
    assert_eq!(rpn::negotiate(&good).param_mask, u::RFCOMM_RPN_PM_ALL);
}

#[test]
fn an_out_of_range_bit_rate_is_refused_and_reported() {
    let mut r = req(u::RFCOMM_RPN_PM_BITRATE);
    r.bit_rate = u::RFCOMM_RPN_BR_230400 + 1;
    let reply = rpn::negotiate(&r);
    assert_eq!(reply.bit_rate, u::RFCOMM_RPN_BR_9600);
    assert_eq!(reply.param_mask & u::RFCOMM_RPN_PM_BITRATE, 0);
}

#[test]
fn a_query_reports_the_standing_values_under_the_full_mask() {
    let r = rpn::query_reply(6);
    assert_eq!(r.dlci, 6);
    assert_eq!(r.param_mask, u::RFCOMM_RPN_PM_ALL);
    assert_eq!(r.bit_rate, u::RFCOMM_RPN_BR_9600);
    assert_eq!(r.xon_char, u::RFCOMM_RPN_XON_CHAR);
    assert_eq!(r.xoff_char, u::RFCOMM_RPN_XOFF_CHAR);
}
