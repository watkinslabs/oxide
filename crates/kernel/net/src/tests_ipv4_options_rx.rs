// Receive-path coverage for the IPv4 header option area: a datagram arriving
// with an option area reaches its socket with the area FILLED, and one whose
// area does not parse reaches no socket at all.

use alloc::vec::Vec;

use crate::ipv4::{ip_checksum, IPV4_HDR_LEN};
use crate::ipv4_options::uapi::{IPOPT_END, IPOPT_RR, IPOPT_TIMESTAMP, IPOPT_TS_TSONLY};
use crate::stack::NetStack;
use crate::udp::UDP_HDR_LEN;
use crate::{IpProto, Ipv4Addr, Ipv4Hdr};

const PORT: u16 = 4400;

/// One IPv4 UDP datagram carrying `area` in its header option area, addressed
/// loopback to loopback so no route or neighbour is needed. The header
/// checksum is computed over the option area too, and the UDP checksum is left
/// off, which a receiver is required to accept.
fn datagram(area: &[u8], body: &[u8]) -> Vec<u8> {
    let hlen = IPV4_HDR_LEN + area.len();
    let mut frame = alloc::vec![0u8; hlen + UDP_HDR_LEN + body.len()];
    let ip = Ipv4Hdr::build(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, IpProto::Udp,
        (area.len() + UDP_HDR_LEN + body.len()) as u16, 1);
    ip.write_to(&mut frame[..IPV4_HDR_LEN]);
    frame[IPV4_HDR_LEN..hlen].copy_from_slice(area);
    // The header length field must name the option area, and the checksum
    // must cover it.
    frame[0] = 0x40 | (hlen / 4) as u8;
    let total = (frame.len() as u16).to_be_bytes();
    frame[2..4].copy_from_slice(&total);
    frame[10..12].fill(0);
    let sum = ip_checksum(&frame[..hlen]).to_be_bytes();
    frame[10..12].copy_from_slice(&sum);
    frame[hlen..hlen + 2].copy_from_slice(&5100u16.to_be_bytes());
    frame[hlen + 2..hlen + 4].copy_from_slice(&PORT.to_be_bytes());
    frame[hlen + 4..hlen + 6].copy_from_slice(&((UDP_HDR_LEN + body.len()) as u16).to_be_bytes());
    frame[hlen + UDP_HDR_LEN..].copy_from_slice(body);
    frame
}

#[test]
fn a_delivered_datagram_carries_the_filled_option_area_to_its_socket() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, PORT).unwrap();
    let area = [IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END];
    stack.deliver_rx(id, &datagram(&area, b"opt")).unwrap();
    let d = endpoint.recv(false).expect("the datagram reaches its socket");
    assert_eq!(d.payload, b"opt");
    // The record-route slot holds the address this host answered on, and the
    // pointer moved past it — neither is true of the area as it arrived.
    assert_eq!(&d.options.data[3..7], &Ipv4Addr::LOOPBACK.octets());
    assert_eq!(d.options.data[2], 8);
    assert!(d.options.rr_needaddr);
}

#[test]
fn a_delivered_timestamp_option_reaches_its_socket_stamped() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, PORT).unwrap();
    let area = [IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_TSONLY, 0, 0, 0, 0, 0, 0, 0, 0];
    stack.deliver_rx(id, &datagram(&area, b"ts")).unwrap();
    let d = endpoint.recv(false).expect("the datagram reaches its socket");
    assert_eq!(d.options.data[2], 9);
    assert!(d.options.ts_needtime);
    // The stamp the fill pass wrote, whatever the hosted clock reads.
    assert_eq!(&d.options.data[4..8], &crate::ipv4_options::timestamp().to_be_bytes());
}

#[test]
fn a_header_whose_option_area_does_not_parse_reaches_no_socket() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, PORT).unwrap();
    // A record route whose declared length overruns the area.
    let area = [IPOPT_RR, 40, 4, 0, 0, 0, 0, 0];
    assert!(stack.deliver_rx(id, &datagram(&area, b"bad")).is_err());
    assert!(endpoint.recv(false).is_none());
}

#[test]
fn a_header_with_no_option_area_is_delivered_untouched() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, PORT).unwrap();
    stack.deliver_rx(id, &datagram(&[], b"plain")).unwrap();
    let d = endpoint.recv(false).expect("the datagram reaches its socket");
    assert_eq!(d.payload, b"plain");
    assert!(d.options.is_empty());
}
