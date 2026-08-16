use super::support::eth_frame;
use crate::flags::{VLAN_FLAG_GVRP, VLAN_FLAG_REORDER_HDR};
use crate::tci::{encode, strip};
use crate::uapi::{ETH_P_8021AD, ETH_P_8021Q};
use crate::xmit::*;

const DST: [u8; 6] = [0x02, 1, 1, 1, 1, 1];
const SRC: [u8; 6] = [0x02, 2, 2, 2, 2, 2];
const IPV4: u16 = 0x0800;

#[test]
fn out_of_band_tagging_is_the_default_behaviour() {
    let flags = VLAN_FLAG_REORDER_HDR;
    assert_eq!(egress_tag_mode(flags, None, ETH_P_8021Q), TagMode::Offload);
    assert_eq!(egress_tag_mode(flags, Some(IPV4), ETH_P_8021Q), TagMode::Offload);
    assert_eq!(egress_tag_mode(flags, Some(ETH_P_8021Q), ETH_P_8021Q), TagMode::Offload);
}

#[test]
fn clearing_reordering_writes_the_tag_into_the_header() {
    assert_eq!(egress_tag_mode(0, None, ETH_P_8021Q), TagMode::Inline);
    assert_eq!(egress_tag_mode(VLAN_FLAG_GVRP, None, ETH_P_8021Q), TagMode::Inline);
}

#[test]
fn a_frame_already_carrying_our_tag_is_left_alone() {
    assert_eq!(egress_tag_mode(0, Some(ETH_P_8021Q), ETH_P_8021Q), TagMode::AlreadyTagged);
    assert_eq!(egress_tag_mode(0, Some(ETH_P_8021AD), ETH_P_8021AD), TagMode::AlreadyTagged);
}

#[test]
fn an_injected_untagged_frame_is_tagged_out_of_band() {
    // A raw sender can hand a complete untagged frame to the interface. It
    // must still leave tagged, even though this interface writes tags inline.
    assert_eq!(egress_tag_mode(0, Some(IPV4), ETH_P_8021Q), TagMode::Offload);
    // A customer tag on a service-tag interface is not our tag either.
    assert_eq!(egress_tag_mode(0, Some(ETH_P_8021Q), ETH_P_8021AD), TagMode::Offload);
}

#[test]
fn inline_placement_produces_a_tagged_frame() {
    let frame = eth_frame(DST, SRC, IPV4, 20);
    let tci = encode(11, 3);
    let out = apply(TagMode::Inline, &frame, ETH_P_8021Q, tci, false).unwrap();
    assert!(out.hw_tag.is_none());
    let (proto, seen, back) = strip(&out.frame).unwrap();
    assert_eq!((proto, seen), (ETH_P_8021Q, tci));
    assert_eq!(back, frame);
}

#[test]
fn an_already_tagged_frame_is_not_tagged_twice() {
    let frame = eth_frame(DST, SRC, IPV4, 20);
    let tagged = crate::tci::insert(&frame, ETH_P_8021Q, encode(11, 0)).unwrap();
    let out = apply(TagMode::AlreadyTagged, &tagged, ETH_P_8021Q, encode(11, 0), false).unwrap();
    assert_eq!(out.frame, tagged);
    assert!(out.hw_tag.is_none());
}

#[test]
fn an_out_of_band_tag_stays_out_of_band_when_the_hardware_inserts_it() {
    let frame = eth_frame(DST, SRC, IPV4, 20);
    let tci = encode(11, 7);
    let out = apply(TagMode::Offload, &frame, ETH_P_8021AD, tci, true).unwrap();
    assert_eq!(out.frame, frame, "the bytes are untouched");
    assert_eq!(out.hw_tag, Some((ETH_P_8021AD, tci)));
}

#[test]
fn an_out_of_band_tag_is_pushed_inside_when_the_hardware_cannot() {
    let frame = eth_frame(DST, SRC, IPV4, 20);
    let tci = encode(11, 7);
    let out = apply(TagMode::Offload, &frame, ETH_P_8021Q, tci, false).unwrap();
    assert!(out.hw_tag.is_none(), "nothing downstream would insert it");
    let (proto, seen, back) = strip(&out.frame).unwrap();
    assert_eq!((proto, seen), (ETH_P_8021Q, tci));
    assert_eq!(back, frame);
}
