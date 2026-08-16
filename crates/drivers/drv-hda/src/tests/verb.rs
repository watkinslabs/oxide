// Provenance: the HD-Audio command word layout and the RIRB response
// extension. A mis-shifted field silently addresses the wrong node.

use super::*;

#[test]
fn a_command_packs_address_node_verb_and_payload() {
    // Address 1, node 0x14, SET_PIN_WIDGET_CONTROL, payload 0x40.
    assert_eq!(make_verb(1, 0x14, SET_PIN_WIDGET_CONTROL, 0x40), Some(0x1147_0740));
    // A wide-payload verb leaves the low 16 bits to the payload.
    assert_eq!(make_verb(0, 2, SET_STREAM_FORMAT, 0x4011), Some(0x0022_4011));
    assert_eq!(verb_addr(0x1147_0740), 1);
}

#[test]
fn an_out_of_range_field_refuses_to_encode_rather_than_truncating() {
    assert_eq!(make_verb(0x10, 2, PARAMETERS, 0), None);
    assert_eq!(make_verb(0, 0x80, PARAMETERS, 0), None);
    assert_eq!(make_verb(0, 2, 0x1000, 0), None);
    assert_eq!(make_verb(MAX_CODEC_ADDRESS, MAX_NID, 0x0fff, 0xffff), Some(0xf7ff_ffff));
}

#[test]
fn a_response_carries_its_codec_address_and_unsolicited_flag() {
    let solicited = decode_response(0x1234_5678, 0x0000_0003);
    assert_eq!(solicited, Response { value: 0x1234_5678, addr: 3, unsolicited: false });
    let unsolicited = decode_response(0x0400_0001, crate::uapi::RIRB_EX_UNSOL_EV | 2);
    assert!(unsolicited.unsolicited);
    assert_eq!(unsolicited.addr, 2);
    // The tag the codec was told to echo comes back in the top six bits.
    assert_eq!(unsol_tag(unsolicited.value), 1);
    assert_eq!(unsolicited.value & UNSOL_RES_PRESENCE, 1);
}

#[test]
fn sub_node_counts_split_into_start_and_length() {
    assert_eq!(sub_nodes(0x0002_0009), (2, 9));
    assert_eq!(sub_nodes(0x0001_0001), (1, 1));
    assert_eq!(sub_nodes(0), (0, 0));
}

#[test]
fn unsolicited_enable_and_stream_assignment_payloads() {
    assert_eq!(unsol_enable_payload(0), 0x80);
    assert_eq!(unsol_enable_payload(5), 0x85);
    // The tag field is six bits; a wider value cannot corrupt the enable bit.
    assert_eq!(unsol_enable_payload(0xff), 0xbf);
    // Stream tag 1, channel 0 — what a stereo playback converter is given.
    assert_eq!(channel_streamid_payload(1, 0), 0x10);
    assert_eq!(channel_streamid_payload(3, 2), 0x32);
}
