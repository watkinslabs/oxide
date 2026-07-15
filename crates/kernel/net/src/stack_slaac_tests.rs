use crate::stack::NetStack;
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
use crate::{IpProto, Ipv6Addr, MacAddr};

#[test]
fn ipv6_slaac_retains_address_lifetimes() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let router = Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    let all_nodes = Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 1]);
    let prefix = Ipv6Addr::from_segments([0x2001, 0xdb8, 0x77, 0, 0, 0, 0, 0]);
    let ra = crate::ndp::RouterAdvertisement::build_one_prefix(
        router,
        all_nodes,
        MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        1800,
        prefix,
        64,
        crate::ndp::NDP_PIO_FLAG_ONLINK | crate::ndp::NDP_PIO_FLAG_AUTO,
    );
    let mut frame = alloc::vec![0u8; IPV6_HDR_LEN + ra.len()];
    let mut hdr = Ipv6Hdr::build(router, all_nodes, IpProto::Icmpv6, ra.len() as u16);
    hdr.hop_limit = u8::MAX;
    hdr.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&ra);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    stack.ipv6_control_tick(0);

    let expected = Ipv6Addr::from_segments([0x2001, 0xdb8, 0x77, 0, 0x0200, 0x00ff, 0xfe00, 0]);
    let (_, row) = stack.v6_addr_snapshot().into_iter()
        .find(|(iface, row)| *iface == id && row.addr == expected)
        .expect("SLAAC metadata row");
    assert_eq!((row.prefixlen, row.valid, row.preferred), (64, 3600, 1800));
}
