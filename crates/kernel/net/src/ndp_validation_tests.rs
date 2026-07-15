use super::*;

fn checksum(mut packet: alloc::vec::Vec<u8>, src: Ipv6Addr, dst: Ipv6Addr)
    -> alloc::vec::Vec<u8>
{
    packet[2] = 0;
    packet[3] = 0;
    let checksum = compute_ndp_checksum(&packet, src, dst);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[test]
fn ns_rejects_zero_truncated_and_wrong_link_layer_options() {
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let target = Ipv6Addr::from_segments([0x2001,0xdb8,1,0,0,0,0,1]);
    let dst = solicited_node_multicast(target);
    let mut zero = NdpMsg::build_ns(src, dst, MacAddr::ZERO, target);
    zero[NDP_HDR_FIXED + 1] = 0;
    assert_eq!(NdpMsg::parse(&checksum(zero, src, dst), src, dst), Err(NdpError::BadOption));

    let mut truncated = NdpMsg::build_ns(src, dst, MacAddr::ZERO, target);
    truncated.pop();
    assert_eq!(NdpMsg::parse(&checksum(truncated, src, dst), src, dst), Err(NdpError::BadOption));

    let mut wrong = NdpMsg::build_ns(src, dst, MacAddr::ZERO, target);
    wrong[NDP_HDR_FIXED] = NDP_OPT_TARGET_LLADDR;
    assert_eq!(NdpMsg::parse(&checksum(wrong, src, dst), src, dst), Err(NdpError::BadOption));
}

#[test]
fn ns_rejects_invalid_source_destination_target_combinations() {
    let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let target = Ipv6Addr::from_segments([0x2001,0xdb8,1,0,0,0,0,1]);
    let dst = solicited_node_multicast(target);
    let with_sll = NdpMsg::build_ns(Ipv6Addr::ANY, dst, MacAddr::ZERO, target);
    assert_eq!(NdpMsg::parse(&with_sll, Ipv6Addr::ANY, dst), Err(NdpError::BadOption));

    let wrong_dst = IPV6_ALL_NODES;
    let wrong_dest = NdpMsg::build_ns(src, wrong_dst, MacAddr::ZERO, target);
    assert_eq!(NdpMsg::parse(&wrong_dest, src, wrong_dst), Err(NdpError::BadAddress));

    let multicast_target = IPV6_ALL_NODES;
    let multicast_dst = solicited_node_multicast(multicast_target);
    let wrong_target = NdpMsg::build_ns(src, multicast_dst, MacAddr::ZERO, multicast_target);
    assert_eq!(NdpMsg::parse(&wrong_target, src, multicast_dst), Err(NdpError::BadAddress));
}

#[test]
fn na_rejects_unspecified_source_and_solicited_multicast_destination() {
    let target = Ipv6Addr::from_segments([0x2001,0xdb8,1,0,0,0,0,1]);
    let peer = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let unspecified = NdpMsg::build_na(Ipv6Addr::ANY, peer, MacAddr::ZERO, target, 0);
    assert_eq!(NdpMsg::parse(&unspecified, Ipv6Addr::ANY, peer), Err(NdpError::BadAddress));

    let solicited_multicast = NdpMsg::build_na(peer, IPV6_ALL_NODES, MacAddr::ZERO, target, 0);
    assert_eq!(NdpMsg::parse(&solicited_multicast, peer, IPV6_ALL_NODES),
        Err(NdpError::BadAddress));
}
