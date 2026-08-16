use super::support::eth_frame;
use crate::tci::*;
use crate::uapi::{ETH_P_8021AD, ETH_P_8021Q, VLAN_ETH_HLEN, VLAN_HLEN};

const DST: [u8; 6] = [0xff; 6];
const SRC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
const IPV4: u16 = 0x0800;

#[test]
fn round_trip_every_code_point() {
    for pcp_value in 0u8..8 {
        for id in [0u16, 1, 2, 100, 4093, 4094] {
            let t = encode(id, pcp_value);
            assert_eq!(vlan_id(t), id, "id {id} pcp {pcp_value}");
            assert_eq!(pcp(t), pcp_value, "id {id} pcp {pcp_value}");
            assert!(!cfi(t), "transmit path never sets drop-eligible");
        }
    }
}

#[test]
fn identifier_zero_is_a_real_tag() {
    let t = encode(0, 5);
    assert_eq!(vlan_id(t), 0);
    assert_eq!(pcp(t), 5);
    assert_ne!(t, 0, "priority alone still makes a non-zero tag");
}

#[test]
fn identifier_bits_do_not_reach_the_priority_field() {
    // 4095 is reserved and refused at creation, but the encoder must still
    // keep it out of the neighbouring fields rather than corrupting them.
    let t = encode(0xffff, 0);
    assert_eq!(vlan_id(t), 0x0fff);
    assert_eq!(pcp(t), 0);
    assert!(!cfi(t));
}

#[test]
fn code_point_bits_do_not_reach_the_identifier() {
    let t = encode(0, 0xff);
    assert_eq!(vlan_id(t), 0);
    assert_eq!(pcp(t), 7);
}

#[test]
fn drop_eligible_bit_survives_decode() {
    let raw = 0x1064u16; // identifier 100, drop-eligible set
    assert!(cfi(raw));
    assert_eq!(vlan_id(raw), 100);
}

#[test]
fn insert_then_strip_is_the_original_frame() {
    for len in [0usize, 1, 46, 1500] {
        let original = eth_frame(DST, SRC, IPV4, len);
        let tagged = insert(&original, ETH_P_8021Q, encode(4094, 6)).unwrap();
        assert_eq!(tagged.len(), original.len() + VLAN_HLEN);
        let (proto, t, back) = strip(&tagged).unwrap();
        assert_eq!(proto, ETH_P_8021Q);
        assert_eq!(vlan_id(t), 4094);
        assert_eq!(pcp(t), 6);
        assert_eq!(back, original, "len {len}");
    }
}

#[test]
fn insert_puts_the_tag_after_the_addresses() {
    let original = eth_frame(DST, SRC, IPV4, 8);
    let tagged = insert(&original, ETH_P_8021AD, encode(7, 1)).unwrap();
    assert_eq!(&tagged[..6], &DST);
    assert_eq!(&tagged[6..12], &SRC);
    assert_eq!(&tagged[12..14], &ETH_P_8021AD.to_be_bytes());
    assert_eq!(&tagged[14..16], &encode(7, 1).to_be_bytes());
    assert_eq!(&tagged[16..18], &IPV4.to_be_bytes(), "inner type moved out by four");
    assert_eq!(&tagged[VLAN_ETH_HLEN..], &original[14..], "payload untouched");
}

#[test]
fn strip_rejects_an_untagged_frame() {
    let frame = eth_frame(DST, SRC, IPV4, 20);
    assert_eq!(strip(&frame).unwrap_err(), TagError::NotTagged);
    assert_eq!(peek(&frame).unwrap_err(), TagError::NotTagged);
}

#[test]
fn strip_rejects_a_truncated_tag() {
    let original = eth_frame(DST, SRC, IPV4, 8);
    let tagged = insert(&original, ETH_P_8021Q, encode(3, 0)).unwrap();
    for cut in 0..VLAN_ETH_HLEN {
        assert_eq!(strip(&tagged[..cut]).unwrap_err(), TagError::Short, "cut {cut}");
    }
}

#[test]
fn stacked_tags_strip_outermost_first() {
    let original = eth_frame(DST, SRC, IPV4, 4);
    let inner = insert(&original, ETH_P_8021Q, encode(10, 0)).unwrap();
    let outer = insert(&inner, ETH_P_8021AD, encode(20, 3)).unwrap();
    let (proto, t, rest) = strip(&outer).unwrap();
    assert_eq!(proto, ETH_P_8021AD);
    assert_eq!(vlan_id(t), 20);
    assert_eq!(rest, inner);
    let (proto, t, rest) = strip(&rest).unwrap();
    assert_eq!(proto, ETH_P_8021Q);
    assert_eq!(vlan_id(t), 10);
    assert_eq!(rest, original);
}

#[test]
fn encapsulated_type_is_readable_without_stripping() {
    let tagged = insert(&eth_frame(DST, SRC, IPV4, 4), ETH_P_8021Q, encode(5, 0)).unwrap();
    assert_eq!(inner_ethertype(&tagged).unwrap(), IPV4);
}

#[test]
fn only_tag_protocols_count_as_tags() {
    assert!(is_tpid(ETH_P_8021Q));
    assert!(is_tpid(ETH_P_8021AD));
    assert!(!is_tpid(IPV4));
    assert!(!is_tpid(0x0806));
}
