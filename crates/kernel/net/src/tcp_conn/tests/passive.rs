// ---- what a passive open records off the opening header -------------------

#[test]
fn a_passive_open_records_the_service_class_and_hop_limit_it_arrived_with() {
    // A 20-byte IPv4 header: version/IHL, TOS, then the hop limit at 8.
    let mut packet = [0u8; crate::ipv4::IPV4_HDR_LEN + 20];
    packet[0] = 0x45;
    packet[1] = 0x2c;
    packet[8] = 57;
    assert_eq!(super::passive_rcv_header(&packet, false, 9), (9, 57, 0x2c));
}

#[test]
fn an_ipv6_passive_open_records_nothing_at_the_ipv4_level() {
    let packet = [0u8; 60];
    assert_eq!(super::passive_rcv_header(&packet, true, 9), (0, 0, 0));
}

#[test]
fn an_ipv6_passive_open_records_traffic_class_and_flow_label() {
    let mut packet = [0u8; crate::ipv6::IPV6_HDR_LEN];
    packet[..4].copy_from_slice(&0x62c5_4321u32.to_be_bytes());
    assert_eq!(super::passive_v6_flowinfo(&packet, true), 0x02c5_4321);
    assert_eq!(super::passive_v6_flowinfo(&packet, false), 0);
    assert_eq!(super::passive_v6_flowinfo(&packet[..12], true), 0);
}

#[test]
fn a_packet_too_short_to_hold_a_header_records_nothing() {
    assert_eq!(super::passive_rcv_header(&[0x45, 0x2c, 0, 0], false, 9), (0, 0, 0));
}
