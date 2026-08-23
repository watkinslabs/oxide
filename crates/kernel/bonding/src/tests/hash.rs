// Transmit-hash contract: exact output per policy for one synthetic flow, and
// which fields each policy is sensitive to.

use crate::hash::{bond_xmit_hash, dissect, eth_hash, hash_to_index, is_igmp, vlan_srcmac_hash,
                  FlowKeys};
use alloc::vec;
use crate::uapi::{
    BOND_XMIT_POLICY_ENCAP23, BOND_XMIT_POLICY_ENCAP34, BOND_XMIT_POLICY_LAYER2,
    BOND_XMIT_POLICY_LAYER23, BOND_XMIT_POLICY_LAYER34, BOND_XMIT_POLICY_VLAN_SRCMAC,
};

const DST: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];
const SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x22];
const ETH_P_IP: u16 = 0x0800;

fn flow() -> FlowKeys {
    FlowKeys {
        dst_mac: DST, src_mac: SRC, eth_proto: ETH_P_IP, vlan: 0,
        l3_src: u32::from_ne_bytes([10, 0, 0, 1]),
        l3_dst: u32::from_ne_bytes([10, 0, 0, 2]),
        ports: u32::from_ne_bytes([0x04, 0xD2, 0x00, 0x50]),
        icmp_id: 0, dissected: true, l4_hash: None,
    }
}

#[test]
fn layer2_is_the_low_octet_and_ethertype_fold() {
    assert_eq!(eth_hash(&flow()), 0x0000_0833);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER2, &flow()), 0x0000_0833);
}

#[test]
fn layer23_mixes_addresses_without_discarding_a_bit() {
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER23, &flow()), 0x0303_0b38);
}

#[test]
fn layer34_hashes_ports_and_discards_the_low_bit() {
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &flow()), 0x29a9_c0c2);
}

#[test]
fn encap_policies_match_their_non_encap_counterparts_without_an_inner_header() {
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_ENCAP23, &flow()), 0x0303_0b38);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_ENCAP34, &flow()), 0x29a9_c0c2);
}

#[test]
fn encap34_short_circuits_to_an_attached_layer4_hash() {
    let mut f = flow();
    f.l4_hash = Some(0xdead_beef);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_ENCAP34, &f), 0xdead_beef);
    // No other policy consults it.
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &f), 0x29a9_c0c2);
}

#[test]
fn vlan_srcmac_folds_the_tag_with_both_halves_of_the_source() {
    let mut f = flow();
    assert_eq!(vlan_srcmac_hash(&f), 0x0002_0022);
    f.vlan = 100;
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_VLAN_SRCMAC, &f), 0x0002_0046);
}

#[test]
fn layer2_ignores_addresses_and_ports_it_does_not_read() {
    let a = flow();
    let mut b = flow();
    b.l3_src = u32::from_ne_bytes([192, 168, 1, 1]);
    b.l3_dst = u32::from_ne_bytes([192, 168, 1, 2]);
    b.ports = u32::from_ne_bytes([0x00, 0x35, 0x1f, 0x90]);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER2, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER2, &b));
}

#[test]
fn layer2_separates_flows_differing_in_the_low_source_octet() {
    let a = flow();
    let mut b = flow();
    b.src_mac[5] = 0x23;
    assert_ne!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER2, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER2, &b));
}

#[test]
fn layer23_ignores_ports_but_separates_addresses() {
    let a = flow();
    let mut ports_only = flow();
    ports_only.ports = u32::from_ne_bytes([0x00, 0x35, 0x1f, 0x90]);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER23, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER23, &ports_only));

    let mut addr = flow();
    addr.l3_dst = u32::from_ne_bytes([10, 0, 0, 3]);
    assert_ne!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER23, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER23, &addr));
}

#[test]
fn layer34_ignores_link_addresses_but_separates_ports() {
    let a = flow();
    let mut macs = flow();
    macs.dst_mac[5] = 0xaa;
    macs.src_mac[5] = 0xbb;
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &macs));

    let mut p = flow();
    p.ports = u32::from_ne_bytes([0x04, 0xD3, 0x00, 0x50]);
    assert_ne!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &p));
}

#[test]
fn vlan_srcmac_ignores_the_destination_but_separates_the_vendor_half() {
    let a = flow();
    let mut d = flow();
    d.dst_mac = [0xff; 6];
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_VLAN_SRCMAC, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_VLAN_SRCMAC, &d));

    let mut v = flow();
    v.src_mac[0] = 0x06;
    assert_ne!(bond_xmit_hash(BOND_XMIT_POLICY_VLAN_SRCMAC, &a),
               bond_xmit_hash(BOND_XMIT_POLICY_VLAN_SRCMAC, &v));
}

#[test]
fn an_undissected_frame_falls_back_to_the_link_layer_fold() {
    let mut f = flow();
    f.dissected = false;
    for p in [BOND_XMIT_POLICY_LAYER23, BOND_XMIT_POLICY_LAYER34, BOND_XMIT_POLICY_ENCAP23] {
        assert_eq!(bond_xmit_hash(p, &f), 0x0000_0833);
    }
}

#[test]
fn an_icmp_identifier_replaces_the_port_word() {
    let mut f = flow();
    f.icmp_id = 0x0000_1234;
    f.ports = 0;
    let with_id = bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &f);
    f.icmp_id = 0x0000_5678;
    assert_ne!(with_id, bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &f));
}

fn ipv4_tcp_frame(sport: u16, dport: u16, dip: [u8; 4]) -> [u8; 54] {
    let mut f = [0u8; 54];
    f[0..6].copy_from_slice(&DST);
    f[6..12].copy_from_slice(&SRC);
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    f[14] = 0x45;
    f[14 + 9] = 6;
    f[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, 1]);
    f[14 + 16..14 + 20].copy_from_slice(&dip);
    f[34..36].copy_from_slice(&sport.to_be_bytes());
    f[36..38].copy_from_slice(&dport.to_be_bytes());
    f
}

#[test]
fn dissecting_a_real_frame_reproduces_the_hand_built_keys() {
    let frame = ipv4_tcp_frame(1234, 80, [10, 0, 0, 2]);
    let fk = dissect(&frame);
    assert!(fk.dissected);
    assert_eq!(fk.dst_mac, DST);
    assert_eq!(fk.src_mac, SRC);
    assert_eq!(fk.eth_proto, ETH_P_IP);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &fk), 0x29a9_c0c2);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER2, &fk), 0x0000_0833);
}

#[test]
fn encap_policies_use_the_inner_ip_and_transport_flow() {
    // IPv4-in-IPv4: the outer addresses identify the tunnel, while Linux's
    // encapsulation-aware flow dissector supplies the inner addresses/ports.
    let mut frame = vec![0u8; 14 + 20 + 20 + 20];
    frame[0..6].copy_from_slice(&DST);
    frame[6..12].copy_from_slice(&SRC);
    frame[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    frame[14] = 0x45; frame[14 + 9] = 4;
    frame[14 + 12..14 + 16].copy_from_slice(&[192, 0, 2, 1]);
    frame[14 + 16..14 + 20].copy_from_slice(&[192, 0, 2, 2]);
    let inner = 34;
    frame[inner] = 0x45; frame[inner + 9] = 6;
    frame[inner + 12..inner + 16].copy_from_slice(&[10, 0, 0, 1]);
    frame[inner + 16..inner + 20].copy_from_slice(&[10, 0, 0, 2]);
    frame[inner + 20..inner + 22].copy_from_slice(&1234u16.to_be_bytes());
    frame[inner + 22..inner + 24].copy_from_slice(&80u16.to_be_bytes());
    let fk = dissect(&frame);
    assert_eq!(fk.l3_src, u32::from_ne_bytes([10, 0, 0, 1]));
    assert_eq!(fk.l3_dst, u32::from_ne_bytes([10, 0, 0, 2]));
    assert_eq!(fk.ports, u32::from_ne_bytes([0x04, 0xd2, 0, 0x50]));
    let outer = FlowKeys { l3_src: u32::from_ne_bytes([192, 0, 2, 1]),
        l3_dst: u32::from_ne_bytes([192, 0, 2, 2]),
        ports: u32::from_ne_bytes([0x13, 0x88, 0x13, 0x89]), ..fk };
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_ENCAP34, &fk),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &fk));
    assert_ne!(bond_xmit_hash(BOND_XMIT_POLICY_ENCAP34, &fk),
               bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &outer));
}

#[test]
fn a_vlan_tag_is_stripped_before_the_inner_ethertype_is_read() {
    let inner = ipv4_tcp_frame(1234, 80, [10, 0, 0, 2]);
    let mut tagged = [0u8; 58];
    tagged[0..12].copy_from_slice(&inner[0..12]);
    tagged[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    tagged[14..16].copy_from_slice(&100u16.to_be_bytes());
    tagged[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes());
    tagged[18..].copy_from_slice(&inner[14..]);
    let fk = dissect(&tagged);
    assert_eq!(fk.vlan, 100);
    assert_eq!(fk.eth_proto, ETH_P_IP);
    assert!(fk.dissected);
    assert_eq!(bond_xmit_hash(BOND_XMIT_POLICY_LAYER34, &fk), 0x29a9_c0c2);
}

#[test]
fn a_frame_too_short_for_a_link_header_dissects_to_nothing() {
    let fk = dissect(&[0u8; 8]);
    assert!(!fk.dissected);
    assert_eq!(fk.eth_proto, 0);
}

#[test]
fn group_membership_reports_are_recognised_only_over_ipv4() {
    let mut frame = ipv4_tcp_frame(0, 0, [224, 0, 0, 1]);
    assert!(!is_igmp(&frame));
    frame[14 + 9] = 2;
    assert!(is_igmp(&frame));
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    assert!(!is_igmp(&frame));
}

#[test]
fn reduction_is_a_plain_modulo_and_an_empty_array_selects_nothing() {
    assert_eq!(hash_to_index(0x29a9_c0c2, 3), Some((0x29a9_c0c2usize) % 3));
    assert_eq!(hash_to_index(7, 0), None);
}
