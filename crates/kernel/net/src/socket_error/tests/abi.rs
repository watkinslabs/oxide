use syscall::errno::Errno;

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::socket_error::abi::{cmsg_slot, errhdr_bytes, extended_err_bytes, name_bytes,
    sockaddr_bytes, supports_name, supports_offender, AF_INET, AF_INET6, IPPROTO_IP, IPPROTO_IPV6,
    IPV6_RECVERR, IP_RECVERR, SOCKADDR_IN6_LEN, SOCKADDR_IN_LEN};
use crate::socket_error::{SocketErrorEntry, SCM_TSTAMP_SND, SOCK_EXTENDED_ERR_LEN,
    SO_EE_CODE_ZEROCOPY_COPIED, SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6, SO_EE_ORIGIN_LOCAL,
    SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_TXTIME, SO_EE_ORIGIN_ZEROCOPY};

use super::{icmp4, icmp6};

#[test]
fn extended_error_head_places_every_field_at_its_wire_offset() {
    let mut entry = icmp4(Errno::Ehostunreach);
    entry.kind = 3;
    entry.code = 4;
    entry.info = 0x1122_3344;
    entry.data = 0x5566_7788;
    let bytes = extended_err_bytes(&entry);
    assert_eq!(bytes.len(), SOCK_EXTENDED_ERR_LEN);
    assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        Errno::Ehostunreach as u32);
    assert_eq!(bytes[4], SO_EE_ORIGIN_ICMP);
    assert_eq!(bytes[5], 3);
    assert_eq!(bytes[6], 4);
    assert_eq!(bytes[7], 0, "the pad byte stays zero");
    assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 0x1122_3344);
    assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 0x5566_7788);
}

#[test]
fn zerocopy_range_occupies_the_info_and_data_words() {
    let bytes = extended_err_bytes(&SocketErrorEntry::zerocopy(3, 11, true, false));
    assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 0);
    assert_eq!(bytes[4], SO_EE_ORIGIN_ZEROCOPY);
    assert_eq!(bytes[6], SO_EE_CODE_ZEROCOPY_COPIED);
    assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 3);
    assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 11);
}

#[test]
fn ancillary_slot_and_record_size_follow_the_socket_family() {
    assert_eq!(cmsg_slot(false), (IPPROTO_IP, IP_RECVERR));
    assert_eq!(cmsg_slot(true), (IPPROTO_IPV6, IPV6_RECVERR));
    assert_eq!(errhdr_bytes(&icmp4(Errno::Ehostunreach), false, false).len(),
        SOCK_EXTENDED_ERR_LEN + SOCKADDR_IN_LEN);
    assert_eq!(errhdr_bytes(&icmp6(Errno::Ehostunreach), true, false).len(),
        SOCK_EXTENDED_ERR_LEN + SOCKADDR_IN6_LEN);
}

#[test]
fn a_received_icmp_error_names_its_speaker() {
    let bytes = errhdr_bytes(&icmp4(Errno::Ehostunreach), false, false);
    let offender = &bytes[SOCK_EXTENDED_ERR_LEN..];
    assert_eq!(u16::from_ne_bytes(offender[0..2].try_into().unwrap()), AF_INET);
    assert_eq!(offender[4..8], Ipv4Addr::LOOPBACK.octets());
    let bytes = errhdr_bytes(&icmp6(Errno::Ehostunreach), true, false);
    let offender = &bytes[SOCK_EXTENDED_ERR_LEN..];
    assert_eq!(u16::from_ne_bytes(offender[0..2].try_into().unwrap()), AF_INET6);
    assert_eq!(offender[8..24], Ipv6Addr::LOOPBACK.0);
}

#[test]
fn a_local_error_names_no_offender() {
    let entry = SocketErrorEntry::local(Errno::Emsgsize as i32,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 53, 1280);
    assert!(!supports_offender(SO_EE_ORIGIN_LOCAL, false, 7, true));
    assert!(!supports_offender(SO_EE_ORIGIN_LOCAL, true, 7, true));
    let bytes = errhdr_bytes(&entry, false, false);
    assert!(bytes[SOCK_EXTENDED_ERR_LEN..].iter().all(|byte| *byte == 0));
}

#[test]
fn transmit_completions_name_an_offender_only_with_an_egress_interface() {
    for origin in [SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_ZEROCOPY, SO_EE_ORIGIN_TXTIME] {
        assert!(!supports_offender(origin, true, 0, true), "no interface, no offender");
        assert!(supports_offender(origin, true, 3, false), "IPv6 needs no extra request");
        assert!(!supports_offender(origin, false, 3, false),
            "IPv4 answers only when the socket asked for ancillary data");
        assert!(supports_offender(origin, false, 3, true));
    }
}

#[test]
fn msg_name_is_reported_for_addressable_origins_only() {
    assert!(supports_name(SO_EE_ORIGIN_ICMP, false, 0));
    assert!(supports_name(SO_EE_ORIGIN_LOCAL, false, 0));
    assert!(!supports_name(SO_EE_ORIGIN_ICMP6, false, 0));
    assert!(supports_name(SO_EE_ORIGIN_ICMP6, true, 0));
    assert!(supports_name(SO_EE_ORIGIN_ICMP, true, 0));
    assert!(!supports_name(SO_EE_ORIGIN_ZEROCOPY, true, 0));
    assert!(supports_name(SO_EE_ORIGIN_ZEROCOPY, true, 53), "a recorded port is addressable");

    assert!(name_bytes(&SocketErrorEntry::zerocopy(0, 0, true, false), false).is_none());
    let named = name_bytes(&icmp4(Errno::Ehostunreach), false).expect("ICMP records a name");
    assert_eq!(u16::from_ne_bytes(named[0..2].try_into().unwrap()), AF_INET);
    assert_eq!(u16::from_be_bytes(named[2..4].try_into().unwrap()), 53);
    assert_eq!(named[4..8], Ipv4Addr::new(192, 0, 2, 1).octets());
}

#[test]
fn an_ipv6_socket_reports_a_v4_destination_as_a_mapped_address() {
    let mut entry = icmp4(Errno::Ehostunreach);
    entry.destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let named = name_bytes(&entry, true).expect("mapped destination is addressable");
    assert_eq!(named.len(), SOCKADDR_IN6_LEN);
    assert_eq!(u16::from_ne_bytes(named[0..2].try_into().unwrap()), AF_INET6);
    assert_eq!(named[8..24], Ipv6Addr::from_v4_mapped(Ipv4Addr::new(198, 51, 100, 7)).0);
    assert_eq!(u32::from_ne_bytes(named[24..28].try_into().unwrap()), 0,
        "a mapped address carries no scope");
}

#[test]
fn a_link_local_name_carries_the_recording_interface_scope() {
    let link_local = Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    let bytes = sockaddr_bytes(IpAddr::V6(link_local), 53, true, 9);
    assert_eq!(u32::from_ne_bytes(bytes[24..28].try_into().unwrap()), 9);
    let bytes = sockaddr_bytes(IpAddr::V6(Ipv6Addr::LOOPBACK), 53, true, 9);
    assert_eq!(u32::from_ne_bytes(bytes[24..28].try_into().unwrap()), 0);
}

#[test]
fn timestamp_records_report_the_selector_and_key_positions() {
    let bytes = extended_err_bytes(&SocketErrorEntry::timestamping(SCM_TSTAMP_SND, 0x99, false, 2));
    assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), Errno::Enomsg as u32);
    assert_eq!(bytes[4], SO_EE_ORIGIN_TIMESTAMPING);
    assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), SCM_TSTAMP_SND);
    assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 0x99);
}
