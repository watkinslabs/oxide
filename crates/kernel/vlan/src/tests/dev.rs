extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

use net::addr::{MacAddr, NetIfaceId};
use net::netdev::{NetDev, NetError};
use net::pkt::Pkt;
use syscall::errno::Errno;

use super::support::{eth_frame, plain_caps, vlan_on, FakeDev, REAL_MAC};
use crate::dev::{ingress_frame, IngressResult, VlanDev};
use crate::flags::{VLAN_FLAG_GVRP, VLAN_FLAG_MASK, VLAN_FLAG_REORDER_HDR};
use crate::tci::{encode, insert, pcp, strip, vlan_id};
use crate::uapi::{ETH_P_8021Q, VLAN_HLEN};

const DST: [u8; 6] = [0x02, 1, 1, 1, 1, 1];
const IPV4: u16 = 0x0800;

#[test]
fn a_new_interface_takes_the_lower_address_and_ceiling() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 42, ETH_P_8021Q);
    assert_eq!(dev.mac(), MacAddr(REAL_MAC));
    assert_eq!(dev.mtu(), 1500);
    assert_eq!(dev.vlan_id(), 42);
    assert_eq!(dev.flags(), VLAN_FLAG_REORDER_HDR);
}

#[test]
fn an_explicit_address_is_kept() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let own = MacAddr([0x02, 9, 8, 7, 6, 5]);
    let dev = VlanDev::new(String::from("eth0.42"), 42, ETH_P_8021Q, NetIfaceId(1),
                           real.clone() as Arc<dyn NetDev>, plain_caps(1500), own);
    assert_eq!(dev.mac(), own);
}

#[test]
fn frame_size_is_clamped_to_what_the_lower_interface_leaves() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 42, ETH_P_8021Q);
    assert_eq!(dev.set_mtu(1500), Ok(()));
    assert_eq!(dev.mtu(), 1500);
    assert_eq!(dev.set_mtu(1501), Err(NetError::Erange));
    assert_eq!(dev.mtu(), 1500, "a refused size changes nothing");
    assert_eq!(dev.set_mtu(576), Ok(()));
    assert_eq!(dev.mtu(), 576);
}

#[test]
fn unknown_flag_bits_are_refused_and_change_nothing() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 42, ETH_P_8021Q);
    assert_eq!(dev.change_flags(0, !VLAN_FLAG_MASK), Err(Errno::Einval));
    assert_eq!(dev.flags(), VLAN_FLAG_REORDER_HDR);
    assert_eq!(dev.change_flags(VLAN_FLAG_GVRP, VLAN_FLAG_GVRP),
               Ok(VLAN_FLAG_REORDER_HDR | VLAN_FLAG_GVRP));
}

#[test]
fn the_egress_tag_carries_the_identifier_and_the_mapped_code_point() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 4094, ETH_P_8021Q);
    dev.with_maps(|m| m.set_egress(3, 6));
    assert_eq!(dev.egress_tci(3), encode(4094, 6));
    assert_eq!(dev.egress_tci(4), encode(4094, 0), "unmapped priority sends code point 0");
}

#[test]
fn a_transmitted_packet_reaches_the_lower_interface_tagged() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 100, ETH_P_8021Q);
    dev.with_maps(|m| m.set_egress(9, 5));
    let mut pkt = Pkt::new(30);
    pkt.proto = IPV4;
    pkt.tx.priority = 9;
    let body = pkt.data().to_vec();
    dev.xmit_l2_observed(pkt, MacAddr(DST), &mut |_, _, _| {}).unwrap();

    let frames = real.frames();
    assert_eq!(frames.len(), 1);
    let (proto, tci, untagged) = strip(&frames[0]).unwrap();
    assert_eq!(proto, ETH_P_8021Q);
    assert_eq!(vlan_id(tci), 100);
    assert_eq!(pcp(tci), 5);
    assert_eq!(&untagged[..6], &DST);
    assert_eq!(&untagged[6..12], &REAL_MAC, "the interface's own address");
    assert_eq!(&untagged[12..14], &IPV4.to_be_bytes());
    assert_eq!(&untagged[14..], &body[..]);
    assert_eq!(dev.stats().tx_packets, 1);
}

#[test]
fn a_complete_frame_handed_over_is_tagged_too() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 7, ETH_P_8021Q);
    let frame = eth_frame(DST, REAL_MAC, IPV4, 16);
    dev.xmit_raw(&frame).unwrap();
    let sent = real.frames();
    assert_eq!(sent[0].len(), frame.len() + VLAN_HLEN);
    let (_, tci, back) = strip(&sent[0]).unwrap();
    assert_eq!(vlan_id(tci), 7);
    assert_eq!(back, frame);
}

#[test]
fn hardware_vlan_feature_sends_the_tag_out_of_band() {
    let mut real = FakeDev::new("eth0", REAL_MAC, 1500);
    Arc::get_mut(&mut real).unwrap().features = net::netdev::NetDevFeatures(
        net::netdev::NetDevFeatures::HW_VLAN_CTAG_TX);
    let dev = vlan_on(&real, 7, ETH_P_8021Q);
    let frame = eth_frame(DST, REAL_MAC, IPV4, 16);
    dev.xmit_raw(&frame).unwrap();
    assert_eq!(real.tags(), vec![(ETH_P_8021Q, encode(7, 0))]);
    assert_eq!(real.frames(), vec![frame], "hardware owns tag insertion");
}

#[test]
fn a_received_frame_is_delivered_detagged() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 55, ETH_P_8021Q);
    dev.with_maps(|m| m.set_ingress(77, 4));
    let original = eth_frame(DST, REAL_MAC, IPV4, 24);
    let tagged = insert(&original, ETH_P_8021Q, encode(55, 4)).unwrap();
    match dev.ingress(&tagged, encode(55, 4)) {
        IngressResult::Deliver { frame, priority } => {
            assert_eq!(frame, original, "byte for byte, tag removed");
            assert_eq!(priority, 77);
        }
        other => panic!("expected delivery, got {other:?}"),
    }
    assert_eq!(dev.stats().rx_packets, 1);
}

#[test]
fn clearing_reordering_keeps_the_tag_in_the_delivered_bytes() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 55, ETH_P_8021Q);
    dev.set_flags(0);
    let tagged = insert(&eth_frame(DST, REAL_MAC, IPV4, 8), ETH_P_8021Q, encode(55, 0)).unwrap();
    match dev.ingress(&tagged, encode(55, 0)) {
        IngressResult::Deliver { frame, .. } => assert_eq!(frame, tagged),
        other => panic!("expected delivery, got {other:?}"),
    }
}

#[test]
fn a_down_interface_takes_nothing() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = vlan_on(&real, 55, ETH_P_8021Q);
    dev.admin_up_changed(false);
    let tagged = insert(&eth_frame(DST, REAL_MAC, IPV4, 8), ETH_P_8021Q, encode(55, 0)).unwrap();
    assert_eq!(dev.ingress(&tagged, encode(55, 0)), IngressResult::Dropped);
    assert_eq!(dev.stats().rx_packets, 0);
}

#[test]
fn delivered_form_follows_the_reordering_flag() {
    let original = eth_frame(DST, REAL_MAC, IPV4, 12);
    let tagged = insert(&original, ETH_P_8021Q, encode(9, 2)).unwrap();
    assert_eq!(ingress_frame(VLAN_FLAG_REORDER_HDR, &tagged).unwrap(), original);
    assert_eq!(ingress_frame(0, &tagged).unwrap(), tagged);
}
