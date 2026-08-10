// The SYN-RECEIVED acceptance rules, as decisions rather than as effects.
//
// These encode the contract a blind off-path attacker is measured against: it
// must guess the 4-tuple, the receive window AND the sequence this side chose
// for its own SYN-ACK before it can finish, or end, a half-open handshake.

use super::*;
use crate::tcp_hdr::flags;

const SNT_ISN: u32 = 0x1000_0000;
const RCV_ISN: u32 = 0x2000_0000;
const WND: u32 = 64_240;

/// The segment an honest client sends to finish the handshake.
fn completing(flag_bits: u8, seq: u32, ack: u32) -> ReqVerdict {
    request_segment(flag_bits, seq, ack, 0, SNT_ISN, RCV_ISN, WND)
}

#[test]
fn the_completing_acknowledgement_is_one_past_the_syn_ack() {
    assert_eq!(completing(flags::ACK, RCV_ISN.wrapping_add(1), SNT_ISN.wrapping_add(1)),
        ReqVerdict::Complete);
}

#[test]
fn an_acknowledgement_naming_any_other_sequence_cannot_complete_the_handshake() {
    // The whole point of the check: an off-path segment that guessed the
    // 4-tuple and landed in the receive window still has to name the exact
    // sequence this side chose. Every neighbour of the right answer, and the
    // sequence the SYN-ACK itself carried, is refused.
    for wrong in [SNT_ISN, SNT_ISN.wrapping_add(2), SNT_ISN.wrapping_sub(1),
                  SNT_ISN.wrapping_add(1_000), 0, 0xFFFF_FFFF] {
        assert_eq!(completing(flags::ACK, RCV_ISN.wrapping_add(1), wrong),
            ReqVerdict::Reset,
            "an acknowledgement of something never sent completed a handshake");
    }
}

#[test]
fn a_wrong_acknowledgement_is_answered_with_a_reset_not_silence() {
    // The reference answers an unacceptable acknowledgement in a
    // non-synchronised state with a reset. Dropping it silently would leave
    // the peer retransmitting against a request that will never answer.
    assert_eq!(completing(flags::ACK, RCV_ISN.wrapping_add(1), SNT_ISN.wrapping_add(9)),
        ReqVerdict::Reset);
}

#[test]
fn the_acknowledgement_number_is_judged_before_the_receive_window() {
    // A wrong acknowledgement is refused whether or not the segment's
    // sequence is anywhere near the window, so an attacker gains nothing by
    // getting one of the two guesses right.
    assert_eq!(completing(flags::ACK, RCV_ISN.wrapping_add(500_000), SNT_ISN.wrapping_add(4)),
        ReqVerdict::Reset);
}

#[test]
fn a_reset_carrying_a_wrong_acknowledgement_cannot_end_the_request() {
    // Judged before the reset bit: a blind reset that named the window but
    // not the sequence this side sent leaves the half-open alone.
    assert_eq!(completing(flags::RST | flags::ACK, RCV_ISN.wrapping_add(1), SNT_ISN),
        ReqVerdict::Reset);
}

#[test]
fn a_reset_in_window_ends_the_request_and_is_not_answered() {
    assert_eq!(completing(flags::RST, RCV_ISN.wrapping_add(1), 0),
        ReqVerdict::EndRequest { reset: false });
}

#[test]
fn a_reset_outside_the_window_is_dropped_in_silence() {
    assert_eq!(completing(flags::RST, RCV_ISN.wrapping_add(500_000), 0), ReqVerdict::Drop);
}

#[test]
fn a_repeat_of_the_opening_syn_re_solicits_the_answer() {
    assert_eq!(completing(flags::SYN, RCV_ISN, 0), ReqVerdict::ResendSynack);
}

#[test]
fn a_syn_at_a_different_sequence_is_not_the_opening_syn() {
    // It occupies a number inside the window, so it is a second connection
    // attempt on a 4-tuple that already has one: the request ends, with a
    // reset because the segment was not one.
    assert_eq!(completing(flags::SYN, RCV_ISN.wrapping_add(1), 0),
        ReqVerdict::EndRequest { reset: true });
}

#[test]
fn a_crossed_syn_ack_at_the_peers_initial_sequence_reads_as_a_bare_acknowledgement() {
    // The SYN sits before the window and occupies nothing inside it, so it is
    // dropped from the decision and the acknowledgement decides. With a
    // payload the segment reaches the window and completes.
    assert_eq!(request_segment(flags::SYN | flags::ACK, RCV_ISN, SNT_ISN.wrapping_add(1),
        4, SNT_ISN, RCV_ISN, WND), ReqVerdict::Complete);
}

#[test]
fn a_segment_beyond_the_receive_window_is_answered_with_an_acknowledgement() {
    assert_eq!(request_segment(flags::ACK, RCV_ISN.wrapping_add(1).wrapping_add(WND + 1),
        SNT_ISN.wrapping_add(1), 0, SNT_ISN, RCV_ISN, WND), ReqVerdict::AckAndDrop);
}

#[test]
fn a_segment_with_no_acknowledgement_at_all_is_dropped() {
    assert_eq!(completing(0, RCV_ISN.wrapping_add(1), 0), ReqVerdict::Drop);
}

#[test]
fn the_rule_holds_across_the_sequence_wrap() {
    // A request whose SYN-ACK sat just below the wrap completes on the
    // acknowledgement that wrapped past it, and on nothing else.
    let isn = 0xFFFF_FFFFu32;
    assert_eq!(request_segment(flags::ACK, 1, 0, 0, isn, 0, WND), ReqVerdict::Complete);
    assert_eq!(request_segment(flags::ACK, 1, isn, 0, isn, 0, WND), ReqVerdict::Reset);
}

#[test]
fn a_request_window_never_exceeds_what_one_header_field_holds() {
    assert_eq!(synack_window(70_000), SYNACK_WINDOW_MAX);
    assert_eq!(synack_window(1_024), 1_024);
}

// The full-socket rule is a window, not an equality: a fast open, or a child
// already fed its completing acknowledgement, has a real send sequence space.

#[test]
fn a_socket_in_syn_received_accepts_an_acknowledgement_within_its_send_space() {
    assert!(socket_ack_acceptable(SNT_ISN.wrapping_add(1), SNT_ISN, SNT_ISN.wrapping_add(1)));
    assert!(socket_ack_acceptable(SNT_ISN, SNT_ISN, SNT_ISN.wrapping_add(1)),
        "an acknowledgement repeating what is already acknowledged is not stale");
}

#[test]
fn a_socket_in_syn_received_refuses_an_acknowledgement_of_the_unsent() {
    assert!(!socket_ack_acceptable(SNT_ISN.wrapping_add(2), SNT_ISN, SNT_ISN.wrapping_add(1)),
        "an acknowledgement naming a sequence never sent was accepted");
}

#[test]
fn a_socket_in_syn_received_refuses_an_acknowledgement_older_than_its_send_una() {
    assert!(!socket_ack_acceptable(SNT_ISN.wrapping_sub(1), SNT_ISN, SNT_ISN.wrapping_add(1)));
}

#[test]
fn the_socket_rule_holds_across_the_sequence_wrap() {
    assert!(socket_ack_acceptable(0, 0xFFFF_FFFF, 0));
    assert!(!socket_ack_acceptable(1, 0xFFFF_FFFF, 0));
    assert!(!socket_ack_acceptable(0xFFFF_FFFE, 0xFFFF_FFFF, 0));
}
