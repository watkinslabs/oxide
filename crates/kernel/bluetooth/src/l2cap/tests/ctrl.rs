//! The control field in both widths, and the modular sequence arithmetic the
//! window depends on.

use super::*;

#[test]
fn an_information_frame_round_trips_in_the_basic_width() {
    let c = Ctrl { sframe: false, txseq: 5, sar: u::SAR_START, reqseq: 9, poll: false, final_: true, super_: 0 };
    let packed = c.pack_enhanced();
    let back = Ctrl::unpack_enhanced(packed);
    assert_eq!(back.sframe, false);
    assert_eq!(back.txseq, 5);
    assert_eq!(back.sar, u::SAR_START);
    assert_eq!(back.reqseq, 9);
    assert_eq!(back.final_, true);
}

#[test]
fn a_supervisory_frame_round_trips_in_the_basic_width() {
    let c = Ctrl { sframe: true, super_: u::SUPER_SREJ, reqseq: 3, poll: true, ..Ctrl::default() };
    let back = Ctrl::unpack_enhanced(c.pack_enhanced());
    assert!(back.sframe);
    assert_eq!(back.super_, u::SUPER_SREJ);
    assert_eq!(back.reqseq, 3);
    assert!(back.poll);
    assert_eq!(back.txseq, 0);
    assert_eq!(back.sar, 0);
}

#[test]
fn an_information_frame_round_trips_in_the_extended_width() {
    let c = Ctrl { sframe: false, txseq: 1000, sar: u::SAR_CONTINUE, reqseq: 2000, ..Ctrl::default() };
    let back = Ctrl::unpack_extended(c.pack_extended());
    assert_eq!(back.txseq, 1000);
    assert_eq!(back.sar, u::SAR_CONTINUE);
    assert_eq!(back.reqseq, 2000);
    assert!(!back.sframe);
}

#[test]
fn a_supervisory_frame_round_trips_in_the_extended_width() {
    let c = Ctrl { sframe: true, super_: u::SUPER_RNR, reqseq: 2000, poll: true, final_: true, ..Ctrl::default() };
    let back = Ctrl::unpack_extended(c.pack_extended());
    assert!(back.sframe);
    assert_eq!(back.super_, u::SUPER_RNR);
    assert_eq!(back.reqseq, 2000);
    assert!(back.poll);
    assert!(back.final_);
}

#[test]
fn the_frame_type_bit_is_what_separates_the_two_kinds() {
    assert_eq!(Ctrl::sframe(u::SUPER_RR, 0).pack_enhanced() & u::CTRL_FRAME_TYPE, u::CTRL_FRAME_TYPE);
    assert_eq!(Ctrl::iframe(0, 0, 0).pack_enhanced() & u::CTRL_FRAME_TYPE, 0);
    assert_eq!(Ctrl::sframe(u::SUPER_RR, 0).pack_extended() & u::EXT_CTRL_FRAME_TYPE, u::EXT_CTRL_FRAME_TYPE);
    assert_eq!(Ctrl::iframe(0, 0, 0).pack_extended() & u::EXT_CTRL_FRAME_TYPE, 0);
}

#[test]
fn the_two_widths_occupy_the_bytes_their_size_says() {
    let c = Ctrl::iframe(1, 0, 2);
    assert_eq!(&c.pack(false)[..u::ENH_CTRL_SIZE], &c.pack_enhanced().to_le_bytes());
    assert_eq!(c.pack(false)[2..], [0, 0]);
    assert_eq!(c.pack(true), c.pack_extended().to_le_bytes());
    assert_eq!(ctrl_size(false), u::ENH_CTRL_SIZE);
    assert_eq!(ctrl_size(true), u::EXT_CTRL_SIZE);
    assert_eq!(ertm_hdr_size(false), u::ENH_HDR_SIZE);
    assert_eq!(ertm_hdr_size(true), u::EXT_HDR_SIZE);
}

#[test]
fn a_body_too_short_for_the_width_in_force_has_no_control_field() {
    assert!(Ctrl::unpack(&[0], false).is_none());
    assert!(Ctrl::unpack(&[0, 0, 0], true).is_none());
    assert!(Ctrl::unpack(&[0, 0], false).is_some());
}

#[test]
fn sequence_numbers_wrap_at_the_window_maximum() {
    let m = u::DEFAULT_TX_WINDOW;
    assert_eq!(next_seq(m, 0), 1);
    assert_eq!(next_seq(m, m), 0);
    assert_eq!(seq_offset(m, 5, 3), 2);
    assert_eq!(seq_offset(m, 1, m), 2);
    assert_eq!(seq_offset(m, 0, 0), 0);
}
