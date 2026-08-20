/// What the network header of a passive open's opening packet carried. The
/// first word is the IPv4 input interface or, for IPv6, the received flowinfo;
/// the families are exclusive and avoid growing the interrupt-stack TCB.
/// # C: O(1)
pub fn passive_rcv_header(packet: &[u8], ipv6: bool, iif: u32) -> (u32, u8, u8) {
    if ipv6 { return (passive_v6_flowinfo(packet, true), 0, 0); }
    if packet.len() < crate::ipv4::IPV4_HDR_LEN { return (0, 0, 0); }
    (iif, packet[8], packet[1])
}

/// IPv6 traffic class and flow label carried by a passive open's opening
/// packet. The version nibble is header-owned and never retained. # C: O(1)
pub fn passive_v6_flowinfo(packet: &[u8], ipv6: bool) -> u32 {
    if !ipv6 { return 0; }
    crate::ipv6::Ipv6Hdr::parse(packet).map_or(0, |h|
        crate::cmsg::flowinfo(h.traffic_class, h.flow_label))
}
