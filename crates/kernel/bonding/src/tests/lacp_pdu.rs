// LACPDU wire format: round trip, field placement, and rejection rules.

use crate::flags::{
    LACP_STATE_AGGREGATION, LACP_STATE_COLLECTING, LACP_STATE_DISTRIBUTING,
    LACP_STATE_LACP_ACTIVITY, LACP_STATE_SYNCHRONIZATION,
};
use crate::lacp::pdu::{PduError, TLV_TYPE_ACTOR_INFO, TLV_TYPE_COLLECTOR_INFO,
                       TLV_TYPE_PARTNER_INFO, TLV_TYPE_TERMINATOR};
use crate::lacp::{Lacpdu, PortInfo, LACP_SUBTYPE, LACP_VERSION};
use crate::limits::{AD_COLLECTOR_TLV_LEN, AD_INFO_TLV_LEN, LACPDU_LEN};

fn sample() -> Lacpdu {
    Lacpdu {
        actor: PortInfo {
            system_priority: 0xffff, system: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
            key: 0x0011, port_priority: 0x00ff, port: 0x0003,
            state: LACP_STATE_LACP_ACTIVITY | LACP_STATE_AGGREGATION
                 | LACP_STATE_SYNCHRONIZATION,
        },
        partner: PortInfo {
            system_priority: 0x8000, system: [0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            key: 0x0022, port_priority: 0x0080, port: 0x0007,
            state: LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING,
        },
        collector_max_delay: 0,
    }
}

#[test]
fn encode_then_decode_reproduces_every_field() {
    let pdu = sample();
    let bytes = pdu.encode();
    assert_eq!(bytes.len(), LACPDU_LEN);
    assert_eq!(Lacpdu::decode(&bytes), Ok(pdu));
}

#[test]
fn the_header_and_tlv_chain_sit_where_the_wire_format_puts_them() {
    let b = sample().encode();
    assert_eq!(b[0], LACP_SUBTYPE);
    assert_eq!(b[1], LACP_VERSION);
    assert_eq!(b[2], TLV_TYPE_ACTOR_INFO);
    assert_eq!(b[3], AD_INFO_TLV_LEN);
    assert_eq!(b[22], TLV_TYPE_PARTNER_INFO);
    assert_eq!(b[23], AD_INFO_TLV_LEN);
    assert_eq!(b[42], TLV_TYPE_COLLECTOR_INFO);
    assert_eq!(b[43], AD_COLLECTOR_TLV_LEN);
    assert_eq!(b[58], TLV_TYPE_TERMINATOR);
    assert_eq!(b[59], 0);
}

#[test]
fn multi_octet_fields_are_encoded_most_significant_octet_first() {
    let b = sample().encode();
    assert_eq!(&b[4..6], &[0xff, 0xff]);            // actor system priority
    assert_eq!(&b[6..12], &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&b[12..14], &[0x00, 0x11]);          // actor key
    assert_eq!(&b[16..18], &[0x00, 0x03]);          // actor port
    assert_eq!(&b[24..26], &[0x80, 0x00]);          // partner system priority
    assert_eq!(&b[36..38], &[0x00, 0x07]);          // partner port
}

#[test]
fn the_state_octets_carry_the_actor_and_partner_bits_separately() {
    let b = sample().encode();
    assert_eq!(b[18], LACP_STATE_LACP_ACTIVITY | LACP_STATE_AGGREGATION
                    | LACP_STATE_SYNCHRONIZATION);
    assert_eq!(b[38], LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING);
    assert_ne!(b[18], b[38]);
}

#[test]
fn a_truncated_frame_is_rejected() {
    let b = sample().encode();
    for len in [0usize, 1, 2, 59, LACPDU_LEN - 1] {
        assert_eq!(Lacpdu::decode(&b[..len]), Err(PduError::Truncated));
    }
}

#[test]
fn a_foreign_subtype_is_rejected_before_anything_is_read() {
    let mut b = sample().encode();
    b[0] = 0x02;
    assert_eq!(Lacpdu::decode(&b), Err(PduError::WrongSubtype));
}

#[test]
fn an_unknown_version_is_rejected() {
    let mut b = sample().encode();
    b[1] = 0x02;
    assert_eq!(Lacpdu::decode(&b), Err(PduError::BadVersion));
}

#[test]
fn a_malformed_tlv_chain_is_rejected_at_every_position() {
    for (off, bad) in [(2usize, 0x09u8), (3, 0x10), (22, 0x09), (23, 0x10),
                       (42, 0x09), (43, 0x11), (58, 0x04), (59, 0x08)] {
        let mut b = sample().encode();
        b[off] = bad;
        assert_eq!(Lacpdu::decode(&b), Err(PduError::BadTlv));
    }
}

#[test]
fn trailing_bytes_beyond_the_fixed_body_are_ignored() {
    let b = sample().encode();
    let mut padded = [0u8; LACPDU_LEN + 20];
    padded[..LACPDU_LEN].copy_from_slice(&b);
    assert_eq!(Lacpdu::decode(&padded), Ok(sample()));
}

#[test]
fn building_from_two_port_records_fixes_the_collector_delay() {
    let s = sample();
    let built = Lacpdu::from_ports(s.actor, s.partner);
    assert_eq!(built.collector_max_delay, 0);
    assert_eq!(built.actor, s.actor);
    assert_eq!(built.partner, s.partner);
}

#[test]
fn a_zeroed_frame_is_not_mistaken_for_a_valid_one() {
    assert_eq!(Lacpdu::decode(&[0u8; LACPDU_LEN]), Err(PduError::WrongSubtype));
}
